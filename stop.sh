#!/bin/sh
ps -ef|grep 'Python\ testGroup'|grep -v grep |awk '{print $2}'|xargs kill -9

