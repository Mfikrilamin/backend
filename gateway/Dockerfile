# Use a base image with Java 21 installed
FROM openjdk:21-jdk

# Set the working directory in the container
WORKDIR /app

# Copy the packaged jar file into the container
COPY target/gateway-0.0.1-SNAPSHOT.jar /app/gateway.jar

COPY target/classes/application.yml /app/application.yml 


ENV JAVA_OPTS=""

# Expose the port that the Spring Boot application will run on
EXPOSE 7081

# Fire up our Spring Boot app by default
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -Dspring.config.location=application.yml -jar gateway.jar" ]
