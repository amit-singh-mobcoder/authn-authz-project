export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  moduleFileExtensions: ['ts', 'js'],
  testMatch: ['**/src/test/**/*.test.ts'],
  transformIgnorePatterns: ['<rootDir>/node_modules/'],
};
