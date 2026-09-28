import os
from pathlib import Path
import pytest
from PIL import Image, ImageChops
from playwright.sync_api import Page, expect

K8TRE_DOMAIN = os.getenv("K8TRE_DOMAIN", "dev.k8tre.internal")

HERE = Path(__file__).absolute().parent


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args, playwright):
    return {
        "ignore_https_errors": True,
        "record_video_dir": "screenshots",
        "viewport": {"width": 1280, "height": 720},
    }


def compare_screenshot(test_image, threshold=6, throw=True):
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
    width, height = diff.size
    try:
        data = diff.get_flattened_data()
    except AttributeError:
        data = diff.getdata()

    m = sum(sum(px) for px in data) / width / height
    if throw:
        assert m < threshold, f"Mean pixel difference {m} exceeds threshold {threshold}"
    return m < threshold


def login_to_portal(page: Page) -> None:
    """Login to Portal via Keycloak SSO, completing profile if prompted."""
    page.goto(f"https://portal.{K8TRE_DOMAIN}/login")
    page.wait_for_load_state("networkidle")

    # Keycloak login form
    if page.get_by_role("textbox", name="Username or email").is_visible():
        page.get_by_role("textbox", name="Username or email").fill("trevolution")
        page.get_by_role("textbox", name="Password").fill("k8tre")
        page.get_by_role("button", name="Sign In").click()
        page.wait_for_load_state("networkidle")

    # If Keycloak prompts to complete user profile on first login (Update Account Information)
    if page.locator("input#firstName").is_visible():
        page.locator("input#firstName").fill("TRE")
        page.locator("input#lastName").fill("User")
        page.locator("input[type='submit']").click()
        page.wait_for_load_state("networkidle")

    # Wait for redirect back to portal
    page.wait_for_url(f"https://portal.{K8TRE_DOMAIN}/**")
    page.wait_for_load_state("networkidle")


@pytest.mark.ui
def test_portal_guacamole_vdi(page: Page) -> None:
    """Test Portal login and Guacamole VDI launch with desktop verification."""
    # 1. Login to Portal via Keycloak SSO
    login_to_portal(page)

    # 2. Select Project Apps
    page.goto(f"https://portal.{K8TRE_DOMAIN}/projects/asthma/apps")
    page.wait_for_load_state("networkidle")

    # 3. Launch Guacamole VDI
    page.locator("a[href='/launch/asthma/guacamole']").click()
    page.wait_for_load_state("networkidle")

    # Wait for automatic redirection to Guacamole
    page.wait_for_url("**/guacamole/**", timeout=60000)

    # Wait for desktop to load, take a screenshot to compare
    screenshot = Path("screenshots") / "desktop.png"
    screenshot.parent.mkdir(exist_ok=True)

    matched = False
    for i in range(15):
        page.wait_for_timeout(5000)
        page.screenshot(path=screenshot)
        if compare_screenshot(screenshot, threshold=6, throw=False):
            matched = True
            break
        print(f"Screenshot attempt {i+1} doesn't match yet...")

    assert matched, "Guacamole desktop screenshot did not match reference"

    # 4. Cleanup: Shutdown VDI instance via portal
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"https://portal.{K8TRE_DOMAIN}/vdi")
    page.wait_for_load_state("networkidle")
    shutdown_btn = page.locator("form[action='/shutdown-vdi'] button[type='submit']")
    if shutdown_btn.count() > 0:
        shutdown_btn.first.click()
        page.wait_for_load_state("networkidle")


@pytest.mark.ui
def test_portal_jupyterhub_launch(page: Page) -> None:
    """Test Portal login and JupyterHub workspace launch."""
    # 1. Login to Portal via Keycloak SSO
    login_to_portal(page)

    # 2. Navigate to Asthma project apps
    page.goto(f"https://portal.{K8TRE_DOMAIN}/projects/asthma/apps")
    page.wait_for_load_state("networkidle")

    # 3. Launch JupyterHub
    page.locator("a[href='/launch/asthma/jupyterhub']").click()
    page.wait_for_url("**/hub/**", timeout=30000)

    # 4. Verify profile selection form displays dynamic profile from backend
    expect(page.get_by_text("Asthma Workspace 1")).to_be_visible()
