document$.subscribe(() => {
    if (typeof mermaid === "undefined") {
        return;
    }

    mermaid.initialize({
        startOnLoad: false,
        theme: "neutral",
    });

    mermaid.run({
        querySelector: ".mermaid",
    });
});