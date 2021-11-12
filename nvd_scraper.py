"""
Vulnerability scrapper
nvd database vulnerabilities extractor based on vendor and product and version required by user.
"""

import time
import math
import bleach
import pandas as pd
from selenium import webdriver
from selenium.webdriver.common.by import By
from schema import Schema, And, Use, SchemaError
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support import expected_conditions as ec
from selenium.common.exceptions import TimeoutException, WebDriverException


def main(vendor, product, version):

    # chrome options
    options = webdriver.ChromeOptions()
    options.headless = True
    options.add_argument("start-maximized")
    options.add_argument("disable-infobars")
    options.add_argument("--disable-extensions")
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')
    options.add_experimental_option('excludeSwitches', ['enable-logging'])

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)

    vuln_list = []
    cols = ["cve", "desc", "cvss"]
    num_of_vulns_per_page = 20

    # get url
    url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all" \
          f"&isCpeNameSearch=false&cpe_vendor=cpe:/:{vendor}&cpe_product=cpe:/:{vendor}:{product}" \
          f"&cpe_version=cpe:/:{vendor}:{product}:{version}"
    driver.get(url)
    # print(url)

    total_vulns = driver.find_element(by=By.XPATH,
                                      value='//*[@id="vulnerability-search-results-div"]/div[1]/div[2]/strong').text
    total_pages = math.ceil(int(total_vulns)/num_of_vulns_per_page)

    while True:
        try:
            # get some fields and write them in the a file
            cves = driver.find_elements(by=By.XPATH, value='//*[@id="row"]/table/tbody/tr/th')
            descs = driver.find_elements(by=By.XPATH, value='//*[@id="row"]/table/tbody/tr/td[1]')
            cvsses = driver.find_elements(by=By.XPATH, value='//*[@id="row"]/table/tbody/tr/td[2]')

            for (cve, desc, cvss) in (zip(cves, descs, cvsses)):
                vuln_list.append((cve.text, desc.text, cvss.text))

            current_page_number = driver.find_element(by=By.XPATH, value='//li[@class="active"]/a').text
            print(f"{current_page_number} of {total_pages} pages fetched!")
            # WebDriverWait(driver, 10).until(ec.element_to_be_clickable((By.LINK_TEXT, '>'))).click()
            driver.find_element(by=By.LINK_TEXT, value='>').click()

        except WebDriverException:
            # No more pages
            print("There are not any more pages!")
            driver.quit()
            break

    driver.quit()

    df = pd.DataFrame(vuln_list, columns=cols)
    # print(df)

    # df.to_csv("out.csv", sep='\t')
    df.to_excel("out.xlsx", index=False)


if __name__ == "__main__":

    schema = Schema([{'vendor': And(str, len),
                      'product': And(str, len),
                      'version': And(Use(float), lambda n: n > 0)}])

    vend = bleach.clean(input("Vendor name: "))
    prod = bleach.clean(input("Product name: "))
    ver = bleach.clean(input("Version number: "))

    data = [{'vendor': vend, 'product': prod, 'version': ver}]

    try:
        schema.validate(data)
        print(f"Input data after sanitization and validation:\nvendor: {vend}\nproduct: {prod}\nversion: {ver}")
        main(vend, prod, ver)
        # main('google', 'android', '11.0')

    except SchemaError:
        print(f"Input validation error!")

