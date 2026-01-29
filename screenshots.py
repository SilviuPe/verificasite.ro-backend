from pyppeteer import launch
import base64

async def take_screenshot_base64(url: str, width=1366, height=768) -> str:
    browser = await launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
        ],
    )

    page = await browser.newPage()
    await page.setViewport({"width": width, "height": height})
    await page.goto(url, {"waitUntil": "networkidle2", "timeout": 30000})

    screenshot_bytes = await page.screenshot({"fullPage": True})
    await browser.close()

    return base64.b64encode(screenshot_bytes).decode("utf-8")