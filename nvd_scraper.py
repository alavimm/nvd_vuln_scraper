"""
Vulnerability scrapper
nvd database vulnerabilities extractor based on vendor and product and version required by user.
"""

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

    while True:
        try:
            # get url
            url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&cpe_vendor=cpe:/:{vendor}&cpe_product=cpe:/:{vendor}:{product}&cpe_version=cpe:/:{vendor}:{product}:{version}"
            driver.get(url)

            WebDriverWait(driver, 10).until(ec.visibility_of_element_located((By.XPATH, '//*[@id="refine-search-anchor"]')))

            # get some fields and write them in the a file
            cves = driver.find_elements(by=By.XPATH, value='//*[@id="row"]/table/tbody/tr/th')
            descs = driver.find_elements(by=By.XPATH, value='//*[@id="row"]/table/tbody/tr/td[1]')
            cvsses = driver.find_elements(by=By.XPATH, value='//*[@id="row"]/table/tbody/tr/td[2]')

            for (cve, desc, cvss) in (zip(cves, descs, cvsses)):
                vuln_list.append((cve.text, desc.text, cvss.text))

            WebDriverWait(driver, 10).until(ec.element_to_be_clickable((By.LINK_TEXT, '>')))
            driver.find_element(by=By.LINK_TEXT, value=">").click()
            print("Next page fetched!")

        except TimeoutException:
            print("Time out exception!")
            driver.quit()
            break

        except WebDriverException:
            print("There is no any next page!")
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

    except SchemaError:
        print(f"Input validation error!")

