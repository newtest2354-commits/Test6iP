#!/bin/sh

GRADLE_OPTS="-Xmx2048m"
APP_BASE_NAME=`basename "$0"`
APP_HOME=`dirname "$0"`

exec java $GRADLE_OPTS -classpath "$APP_HOME/gradle/wrapper/gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain "$@"
