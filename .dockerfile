FROM openjdk:17-jdk-slim
WORKDIR /app
COPY target/*.jar verifyemail-0.0.1-SNAPSHOT.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "verifyemail-0.0.1-SNAPSHOT.jar"]