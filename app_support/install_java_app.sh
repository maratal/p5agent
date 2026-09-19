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

# Put the built jar at a fixed place, app.jar in the app dir, so one run command
# ("java -jar app.jar", the java type's default) fits every project whatever its
# build tool names the jar. Skipped: sources/javadoc/test jars, Gradle's
# "-plain" jar and the shade plugin's "original-" leftover — none of them run.
jar=$(ls -t target/*.jar build/libs/*.jar 2>/dev/null \
    | grep -Ev -- '-(sources|javadoc|tests|plain)\.jar$|/original-[^/]*\.jar$' | head -1 || true)
if [[ -n "$jar" ]]; then
    cp -f "$jar" app.jar
    echo "Built jar: $jar -> app.jar"
fi
echo "Java setup complete"

# Service — the app dir is on the unit's PATH (java is in /usr/bin).
create_service "${APP_DIR}"
