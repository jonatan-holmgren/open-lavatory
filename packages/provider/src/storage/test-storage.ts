export const createStorage = (): Storage => {
  const values = new Map<string, string>();

  return {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => { values.set(key, value); },
    removeItem: (key) => { values.delete(key); },
    clear: () => values.clear(),
    key: (index) => {
      let current = 0;

      for (const key of values.keys()) {
        if (current === index) return key;

        current++;
      }

      return null;
    },
    get length() { return values.size; },
  };
};
