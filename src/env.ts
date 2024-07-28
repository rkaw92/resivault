export function env(name: string, defaultValue?: string): string {
    const val = process.env[name];
    if (typeof val === 'string') {
        return val;
    } else if (typeof defaultValue === 'string') {
        return defaultValue;
    } else {
        throw new Error(`Environment value missing: ${name}`);
    }
};
