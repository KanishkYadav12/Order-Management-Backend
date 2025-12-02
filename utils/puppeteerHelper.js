import puppeteer from "puppeteer";

export const launchBrowser = async () => {
    try {
        console.log("Launching browser...");
        const browser = await puppeteer.launch({
            headless: false,  // Run in headless mode (no GUI)
            args: ["--no-sandbox", "--disable-setuid-sandbox"]  // Arguments to bypass sandbox restrictions
        });
        console.log("Browser launched successfully.");
        return browser;
    } catch (error) {
        console.error("Error launching Puppeteer browser:", error);
        throw new Error('Failed to launch Puppeteer');
    }
};
