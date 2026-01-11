# QBit Template: Extension

Template repository for creating QQQ Extension QBits - infrastructure extensions, customizers, and action handlers.

## What is an Extension QBit?

Extension QBits extend or enhance how QQQ operates at the infrastructure/framework level. They provide:
- New backend implementations
- Authentication mechanisms
- Audit capabilities
- Table customizers
- Action handlers

## Quick Start

1. Click "Use this template" to create your QBit
2. Run `scripts/customize_template.py` to rename the example
3. Implement your extension logic
4. Add tests
5. Publish to Maven repository

## Structure

```
src/main/java/com/kingsrook/qbits/example/
├── ExampleExtensionQBitConfig.java    # Configuration
├── ExampleExtensionQBitProducer.java  # Entry point
├── customizers/
│   └── ExampleTableCustomizer.java    # Table customization
└── actions/
    └── ExampleActionCustomizer.java   # Action handling
```

## Key Characteristics

- **No QAppSection** - Pure infrastructure
- **No user-facing tables** (or minimal operational)
- **Wraps existing tables/processes** with new behavior
- **Validates dependencies** on other QQQ components

## Documentation

- [Getting Started](docs/00-getting-started.md)
- [Extension Patterns](docs/01-extension-patterns.md)

## License

AGPL-3.0 - See [LICENSE](LICENSE)
