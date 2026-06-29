#!/usr/bin/env bash
# Standard minimal Java app builder + service. Run from the app directory by
# install_app.sh (with APP_DIR / APP_NAME / APP_PORT / APP_CMD in the env) when
# the cloned repo has no setup.sh/install.sh of its own.
set -e

# Prefer the project's wrapper (needs only a JDK); fall back to the system
# gradle/maven (installed via the 'gradle'/'maven' dependencies) otherwise.
if [[ -x ./gradlew ]]; then
    echo "Building with ./gradlew"
    ./gradlew --no-daemon build
elif [[ -x ./mvnw ]]; then
    echo "Building with ./mvnw"
    ./mvnw -q -DskipTests package
elif [[ -f pom.xml ]]; then
    echo "Building with maven"
    mvn -q -DskipTests package
elif [[ -f build.gradle || -f build.gradle.kts ]]; then
    echo "Building with gradle"
    gradle build
else
    echo "No Gradle/Maven project found — nothing to build"
fi
echo "Java setup complete"

# Service — the app dir is on the unit's PATH (java is in /usr/bin); the run
# command typically points at the built jar, e.g. "java -jar build/libs/app.jar".
create_service "${APP_DIR}"
