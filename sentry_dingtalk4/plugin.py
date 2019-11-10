from __future__ import absolute_import

import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta
from urllib import quote

import requests
import sentry
from django import forms
from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from sentry import tsdb
from sentry.constants import StatsPeriod
from sentry.exceptions import PluginError
from sentry.http import is_valid_url
from sentry.plugins.bases import notify
from sentry.utils.http import absolute_uri


def retry_triple(func):
    def retry_wrapper(*args, **kwargs):
        for i in range(3):
            try:
                return func(*args, **kwargs)
            except:
                continue
        return func(*args, **kwargs)

    return retry_wrapper


def validate_urls4(value, **kwargs):
    output = []
    for url in value.split('\n'):
        url = url.strip()
        if not url:
            continue
        if not url.startswith(('http://', 'https://')):
            raise PluginError('Not a valid URL.')
        if not is_valid_url(url):
            raise PluginError('Not a valid URL.')
        output.append(url)
    return '\n'.join(output)


class DingtalkForm4(notify.NotificationConfigurationForm):
    urls = forms.CharField(
        label=_('Dingtalk robot webhook url'),
        widget=forms.Textarea(attrs={
            'class': 'span6', 'placeholder': 'https://oapi.dingtalk.com/robot/send?access_token=9bacf9b193f'}),
        help_text=_('Enter dingtalk robot webhook url.'))

    secret = forms.CharField(
        label=_('Dingtalk robot secret'),
        widget=forms.Textarea(attrs={
            'class': 'span6', 'placeholder': 'SEC013ee62d708fb270f2c3d2bd20c9aaxxxxx'}),
        help_text=_('Enter dingtalk robot secret.'))

    def clean_url(self):
        value = self.cleaned_data.get('url')
        return validate_urls4(value)


class DingtalkPlugin4(notify.NotificationPlugin):
    author = 'AdamWang'
    author_url = 'https://github.com/AdamWangDoggie/sentry-dingtalk'
    version = sentry.VERSION
    description = "Integrates dingtalk robot(dingtalk version>=4.7.15)."
    resource_links = [
        ('Bug Tracker', 'https://github.com/AdamWangDoggie/sentry-dingtalk/issues'),
        ('Source', 'https://github.com/AdamWangDoggie/sentry-dingtalk'),
    ]

    slug = 'dingtalk4'
    title = 'dingtalk4'
    conf_title = title
    conf_key = 'dingtalk4'

    project_conf_form = DingtalkForm4
    timeout = getattr(settings, 'SENTRY_DINGTALK_TIMEOUT', 3)
    logger = logging.getLogger('sentry.plugins.dingtalk')

    def is_configured(self, project, **kwargs):
        return bool(self.get_option('urls', project)) and bool(self.get_option('secret', project))

    def get_config(self, project, **kwargs):
        return [
            {
                'name': 'urls',
                'label': 'dingtalk robot webhook url',
                'type': 'textarea',
                'help': 'Enter dingtalk robot webhook url.',
                'placeholder': 'https://oapi.dingtalk.com/robot/send?access_token=abcdefg',
                'validators': [validate_urls4],
                'required': True
            },
            {
                'name': 'secret',
                'label': 'dingtalk robot secret',
                'type': 'textarea',
                'help': 'Enter dingtalk robot secret.',
                'placeholder': 'SEC013ee62d708fb270f2c3d2bd20c9aaxxxxx',
                'validators': [],
                'required': True
            },
        ]

    def get_webhook_urls(self, project):
        url = self.get_option('urls', project)
        return url or ''

    def get_secret(self, project):
        secret = self.get_option('secret', project)
        return secret or ''

    def get_group_url(self, group):
        return absolute_uri(group.get_absolute_url())

    def notify_users(self, group, event, *args, **kwargs):
        webhook = self.get_webhook_urls(group.project)
        secret = self.get_secret(group.project)
        millitimestamp = str(int(self.timestamp(datetime.now()) * 1000))
        to_sign = "%s\n%s" % (millitimestamp, secret)
        signed = self.compute_sign(secret, to_sign)
        webhook += "&timestamp=%s&sign=%s" % (millitimestamp, signed)

        data = self.make_message_data(group, event)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        try:
            resp = requests.post(webhook, data=json.dumps(data), headers=headers)
            resp_json = resp.json()
        except Exception as e:
            self.logger.error('[DingtalkPlugin]error when post webhook, %s', str(e))
            return
        if resp_json.get("errcode") != 0:
            self.logger.error('[DingtalkPlugin]errcode: %s, errmsg: %s', str(resp_json.get('errcode')),
                              str(resp_json.get('errmsg')))
            return

    def make_message_data(self, group, event):
        first_seen = (group.first_seen + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")

        seen_in_current_hour = self.seen_in_current_hour(group, event)
        seen_today = self.seen_today(group, event)
        seen_in_total = group.times_seen

        title = "#### [Sentry]Error Occured in %s\n" % event.project.name
        texts = [
            title,
            "Error : %s\n" % event.title,
            "> FirstSeen: %s\n" % first_seen,
            "> Seen In current hour: %d\n" % seen_in_current_hour,
            "> Seen Today: %d\n" % seen_today,
            "> Seen In Total: %d\n" % seen_in_total,
            "[View On Sentry](%s)\n" % self.get_group_url(group),
        ]
        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": "\n".join(texts),
            }
        }

        return data

    def seen_in_current_hour(self, group, event):
        now = timezone.now()
        get_range = retry_triple(tsdb.get_range)
        segments, interval = StatsPeriod(1, timedelta(hours=1))
        environment = event.get_environment()

        query_params = {
            'start': now - ((segments - 1) * interval),
            'end': now,
            'rollup': int(interval.total_seconds()),
        }
        stats = get_range(
            model=tsdb.models.group,
            keys=[group.id],
            environment_ids=environment and [environment.id],
            **query_params
        )
        return stats[group.id][0][1]

    def seen_today(self, group, event):
        now = timezone.now()
        get_range = retry_triple(tsdb.get_range)
        segments, interval = StatsPeriod(1, timedelta(hours=24))
        environment = event.get_environment()

        query_params = {
            'start': now - ((segments - 1) * interval),
            'end': now,
            'rollup': int(interval.total_seconds()),
        }
        stats = get_range(
            model=tsdb.models.group,
            keys=[group.id],
            environment_ids=environment and [environment.id],
            **query_params
        )
        return stats[group.id][0][1]

    def compute_sign(self, secret, content):
        message = content.encode(encoding="utf-8")
        sec = secret.encode(encoding="utf-8")
        return quote(base64.b64encode(hmac.new(sec, message, digestmod=hashlib.sha256).digest()))

    @staticmethod
    def timestamp(dt):
        return int((time.mktime(dt.timetuple()) + dt.microsecond / 1000000.0))
