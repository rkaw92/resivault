export class AbstractFactory<CreatedType, InputType = unknown> {
    private factoriesByType = new Map<string, (input: InputType) => CreatedType>();

    register(typeName: string, concreteFactory: (input: InputType) => CreatedType) {
        if (this.factoriesByType.has(typeName)) {
            throw new Error(`Cannot register factory for type "${typeName}" - type name already taken`);
        }
        this.factoriesByType.set(typeName, concreteFactory);
    }

    create(typeName: string, input: InputType) {
        const concreteFactory = this.factoriesByType.get(typeName);
        if (!concreteFactory) {
            throw new Error(`Cannot construct type name ${typeName} - factory not registered`);
        }
        return concreteFactory(input);
    }
}
