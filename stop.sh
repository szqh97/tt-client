#!/bin/sh
ps -ef|grep 'Python\ TestServ'|grep -v grep |awk '{print $2}'|xargs kill -9

