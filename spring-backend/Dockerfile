FROM openjdk:17-alpine AS build

RUN apk add --no-cache maven

WORKDIR /app

COPY pom.xml .

COPY src src

RUN mvn clean package -DskipTests

FROM openjdk:17-alpine

RUN addgroup -S javagroup && adduser -S javauser -G javagroup

COPY --from=build /app/target/*.jar /app/app.jar

WORKDIR /app

RUN chown javauser:javagroup app.jar

USER javauser

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]