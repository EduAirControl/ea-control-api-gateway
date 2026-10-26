FROM maven:3.9.6-eclipse-temurin-17 AS builder

WORKDIR /app

COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

RUN sed -i 's/\r$//' mvnw && chmod +x mvnw

RUN bash mvnw dependency:go-offline

COPY src src

RUN bash mvnw clean package -DskipTests

FROM eclipse-temurin:17-jre

WORKDIR /app

RUN groupadd -r appgroup && \
    useradd -r -g appgroup appuser
COPY --from=builder /app/target/*.jar app.jar
RUN chown appuser:appgroup app.jar

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=40s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
