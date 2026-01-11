# Getting Started

## Prerequisites

- Java 17+
- Maven 3.8+
- QQQ 0.23.0+

## Creating Your Extension QBit

1. Click "Use this template" on GitHub
2. Clone your new repository
3. Run the customization script:
   ```bash
   python scripts/customize_template.py
   ```
4. Enter your QBit name when prompted

## Project Structure

```
src/main/java/com/kingsrook/qbits/yourextension/
├── YourExtensionQBitConfig.java
├── YourExtensionQBitProducer.java
├── customizers/
└── actions/
```

## Using Your QBit

```java
new YourExtensionQBitProducer()
   .withConfig(new YourExtensionQBitConfig()
      .withTargetTableName("order"))
   .produce(qInstance, "myExtension");
```

## Next Steps

- Read [Extension Patterns](01-extension-patterns.md)
- Implement your customization logic
- Add tests
