export class AbstractFactory<CreatedType, InputParamsType extends Array<any>> {
    private factoriesByType = new Map<string, (...input: InputParamsType) => CreatedType>();

    register(typeName: string, concreteFactory: (...input: InputParamsType) => CreatedType) {
        if (this.factoriesByType.has(typeName)) {
            throw new Error(`Cannot register factory for type "${typeName}" - type name already taken`);
        }
        this.factoriesByType.set(typeName, concreteFactory);
    }

    create(typeName: string, ...input: InputParamsType) {
        const concreteFactory = this.factoriesByType.get(typeName);
        if (!concreteFactory) {
            throw new Error(`Cannot construct type name ${typeName} - factory not registered`);
        }
        return concreteFactory(...input);
    }
}
