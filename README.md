# Phoenix API

Phoenix API is the HTTP interface for connecting external clients and Gryph Labs systems through a stable, versioned
contract.

It is intended to support clients such as custom GPTs using GPT Actions, AI agents and other model-based clients,
internal Gryph Labs services, and future applications that need to communicate with Phoenix or related Gryph systems.

Phoenix API is designed to remain independent of any single AI provider or protocol. MCP may be used as an integration
layer where appropriate, but it is not required. Clients should be able to integrate through normal HTTPS and
OpenAPI-compatible tooling.

## Development

This project is built with:

- Java 21
- Spring Boot
- Gradle

Run the application with:

```bash
./gradlew bootRun
```

Run tests with:

```bash
./gradlew test
```

Build the project with:

```bash
./gradlew build
```

## License

This project is licensed under the Apache License 2.0. See [LICENSE.md](LICENSE.md).

Copyright © Gryph Labs.

The license does not grant permission to use Gryph Labs or Phoenix names, logos, branding, or other trademarks. Forks
and derivative distributions must use their own branding and must not imply endorsement by, sponsorship from, or
affiliation with Gryph Labs without written permission.