import base64
from playwright.async_api import async_playwright

async def take_screenshots_base64(url: str) -> dict:
    async with async_playwright() as p:
        browser = await p.chromium.launch()

        # desktop
        page = await browser.new_page(
            viewport={"width": 1366, "height": 768}
        )
        await page.goto(url, wait_until="networkidle")
        desktop_bytes = await page.screenshot(full_page=False)

        # mobile
        iphone = p.devices["iPhone 12"]
        mobile_page = await browser.new_page(**iphone)
        await mobile_page.goto(url, wait_until="networkidle")
        mobile_bytes = await mobile_page.screenshot(full_page=False)

        await browser.close()

    return {
        "desktop": base64.b64encode(desktop_bytes).decode("ascii"),
        "mobile": base64.b64encode(mobile_bytes).decode("ascii"),
    }
