# build
FROM maven: 3.9.6-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml
COPY src ./src
RUN mvn -DskipTests package

# run
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]