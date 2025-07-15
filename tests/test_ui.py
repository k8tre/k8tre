import os
from pathlib import Path
import pytest
from PIL import Image, ImageChops
from playwright.sync_api import Page  # , expect

K8TRE_DOMAIN = os.getenv("K8TRE_DOMAIN", "dev.k8tre.internal")

HERE = Path(__file__).absolute().parent


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args, playwright):
    return {"ignore_https_errors": True, "record_video_dir": "screenshots"}


def compare_screenshot(test_image, threshold=4, throw=True):
    # Compare images by calculating the mean absolute difference
    # Images must be the same size
    # threshold: Average difference per pixel, this depends on the image type
    # e.g. for 24 bit images (8 bit RGB pixels) threshold=1 means a maximum
    # difference of 1 bit per pixel per channel
    reference = Image.open(HERE / "reference" / "desktop.png")
    test = Image.open(test_image)

    # Absolute difference
    # Convert to RGB, alpha channel breaks ImageChops
    diff = ImageChops.difference(reference.convert("RGB"), test.convert("RGB"))
    diff_data = diff.getdata()

    m = sum(sum(px) for px in diff_data) / diff_data.size[0] / diff_data.size[1]
    if throw:
        assert m < threshold
    return m < threshold


@pytest.mark.ui
def test_jupyter_guacamole(page: Page) -> None:
    # Change this if the project or workspace names are changed
    WORKSPACE_NAME = "k8tre-users-mate"

    page.goto(f"https://jupyter.{K8TRE_DOMAIN}")
    page.get_by_role("button", name="Sign in with keycloak").click()
    page.get_by_role("textbox", name="Username or email").fill("example@example.com")
    page.get_by_role("textbox", name="Password").fill("secret")
    page.get_by_role("button", name="Sign In").click()

    page.get_by_role("button", name="Start My Server").click()
    page.get_by_role("heading", name=WORKSPACE_NAME, exact=True).click()
    page.get_by_role("button", name="Start").click()

    page.get_by_text("Event log").click()
    page.get_by_role("link", name="rdp: https://guacamole.").click()

    # Wait for desktop to load, take a screenshot to compare
    # Use a non temporary folder so we can check it manually if necessary
    screenshot = Path("screenshots") / "desktop.png"

    for i in range(12):
        # Desktop takes a while to load, retry every 10s until the screenshot matches
        page.wait_for_timeout(10000)
        page.screenshot(path=screenshot)
        if compare_screenshot(screenshot, throw=False):
            break
        print("Screenshot doesn't match")

    # Shut down server
    page.goto(f"https://jupyter.{K8TRE_DOMAIN}/hub/home")
    page.get_by_role("button", name="Stop My Server").click()

    compare_screenshot(screenshot)

    # page.keyboard.press("Control+Alt+Shift")
    # expect(page.get_by_role("heading", name="Clipboard")).to_be_visible()
