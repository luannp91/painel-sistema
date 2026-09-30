import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        environment: "happy-dom",
        globals: true,
        include: ["js/**/*.{test,spec}.js"],
        coverage: {
            provider: "v8",
            reporter: ["text", "html", "lcov"],
            include: ["js/**/*.js"],
            exclude: ["js/**/*.test.js", "js/**/*.spec.js", "js/main.js", "js/state.js"],
            thresholds: {
                lines: 70,
                functions: 70,
                branches: 60,
                statements: 70
            }
        }
    }
});
