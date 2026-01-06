module.exports = {
  testEnvironment: 'node',
  transform: {
    '^.+\\.(t|j)sx?$': '@swc/jest', // Use SWC for maximum speed
  },
  // If your library uses ESM (type: module in package.json)
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1', // Handles .js extensions in TS files
  }
};
