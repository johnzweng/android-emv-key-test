#!/bin/sh

#
# Set the loglevel for the classes using SL4J via adb
# Call this script with a log-level as first argument:
#  > ./set_sl4j_loglevels_via_adb.sh INFO
#  > ./set_sl4j_loglevels_via_adb.sh DEBUG
#
adb shell setprop log.tag.EmvParser "$1"
adb shell setprop log.tag.TrackUtils "$1"
adb shell setprop log.tag.DataFactory "$1"
adb shell setprop log.tag.AbstractByteBean "$1"
adb shell setprop log.tag.EnumUtils "$1"
adb shell setprop log.tag.ResponseUtils "$1"
adb shell setprop log.tag.TrackUtils "$1"

