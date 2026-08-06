# ── build ─────────────────────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

COPY pom.xml .
RUN mvn -q -e -DskipTests dependency:go-offline

COPY src ./src
RUN mvn -q -DskipTests package

# ── runtime ───────────────────────────────────────────────────────────────────
# Alpine em vez do JRE completo: superfície de CVE bem menor. fontconfig/ttf-dejavu
# são necessários porque o PDFBox usa AWT ao desenhar o relatório.
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

RUN apk add --no-cache fontconfig ttf-dejavu curl \
    && addgroup -S -g 10001 cyberaudit \
    && adduser  -S -u 10001 -G cyberaudit -h /app cyberaudit

# Copiado com dono definido: o jar fica read-only para o usuário que executa —
# o processo não consegue reescrever o próprio binário.
COPY --from=build --chown=root:root --chmod=444 /app/target/*.jar app.jar

# Container rodava como root. Nada aqui precisa de privilégio: o app não escreve
# em disco (PDF é gerado em memória) e escuta em porta alta.
USER 10001:10001

# A aplicação escuta em server.port (8081). O EXPOSE dizia 8080 e o ENV PORT não
# era lido por nada — divergência que só aparecia na hora de mapear a porta.
EXPOSE 8081
ENV SERVER_PORT=8081

# java.awt.headless: sem isso o AWT do PDFBox tenta abrir display e falha no container.
# MaxRAMPercentage: o default de 25% desperdiça memória em container com limite baixo.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -Djava.awt.headless=true -Djava.security.egd=file:/dev/urandom"

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${SERVER_PORT}/actuator/health" || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
