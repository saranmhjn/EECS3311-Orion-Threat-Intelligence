# Orion Threat Intelligence 

This repository contains the software architecture and design documentation for the Orion Threat Intelligence agent. 

## Contents
* **docs/**: Contains the final Stage 1 PDF report and exported UML diagrams.
* **uml/**: Contains the raw, editable `.uxf` files created using UMLet.

## Architecture Overview
The system relies on a hybrid deterministic and non-deterministic AI architecture, utilizing five core design patterns:
1. **Observer**: For asynchronous UI updates.
2. **Facade**: To encapsulate the AI reasoning engine.
3. **Strategy**: For dynamic tool execution.
4. **Command**: To safely execute and audit remediation actions.
5. **Factory Method**: To instantiate schema-specific threat feed parsers.
