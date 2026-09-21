# AGENTS.md

## Build

```bash
mvn clean compile
```

## Test

```bash
mvn test
```

## Package

```bash
mvn package
```

Produces `target/safe-html-sanitizer-1.0.0-SNAPSHOT.jar`.

## Java Version

Requires JDK 21.

## Dependencies

- jsoup (HTML parsing)
- JUnit 5 (testing, test scope only)
