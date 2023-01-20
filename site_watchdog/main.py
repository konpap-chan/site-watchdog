import difflib
import hashlib
import json
import sys
from typing import Any, Optional

import requests


class Config:
    """
    Configuration handler
    
    Loads configuration from the given file path.
    """

    def __init__(self, config_filepath: str) -> None:
        self.config_filepath: str = config_filepath

    @property
    def config_properties(self) -> dict[str, Any]:
        """Configuration properties from the config file"""

        with open(self.config_filepath) as config_file:
            config = json.load(config_file)
            return config


class Differ:
    """
    Diffing logic for watched entities
    
    Other "diffings" should inherit this class.

    TODO: Create a PageDiffer class that inherits this one and move the methods
        accordingly.
    """

    @staticmethod
    def get_page(url: str):
        """Get text response of given URL"""

        response = requests.get(url)

        return response.text

    @staticmethod
    def find_text_diff(
        baseline_txt: str, input_txt: str, full_diff: bool = False
    ) -> tuple[bool, list[str] | None]:
        """
        Find if there is a difference between two texts, a baseline and an input

        Returns a tuple with:
        - a boolean, True when the text is different, False otherwise
        - optionally the full text difference of the added text
        """

        if baseline_txt != input_txt:

            if full_diff:
                baseline_txt_lines = baseline_txt.splitlines(keepends=True)
                input_txt_lines = input_txt.splitlines(keepends=True)

                d = difflib.Differ()
                difference = list(d.compare(baseline_txt_lines, input_txt_lines))

                # We only care about the items that have been added to baseline_txt compared to
                # before.
                added_difference = [item for item in difference if item.startswith("+   ")]

                return True, added_difference

            else:
                return True, None

        else:
            return False, None

    @staticmethod
    def find_keywords(input_txt: str, and_operation: list[str], or_operation: list[str]) -> bool:
        """Find if the given text matches the 'and'/'or' operations for keywords"""

        # TODO: Return on which keyword it matched
        and_match = False
        or_match = False

        if and_operation is not None:
            and_matches = []

            for keyword in and_operation:
                if any(keyword in txt for txt in input_txt):
                    and_matches.append(True)
                else:
                    and_matches.append(False)

            and_match = all(and_matches)

        if or_operation is not None:
            or_match = any(True if keyword in input_txt else False for keyword in or_operation)

        return any([and_match, or_match])

    @staticmethod
    def save_txt_to_file(filepath: str, txt: str):
        """Save text to the given file"""

        with open(filepath, "w+") as page_file:
            page_file.write(txt)

    def page_diffing(self, path: str, url: str, keywords: dict[str, Any], full_diff) -> tuple[bool, list[str] | None]:
        """
        Find the diff of a website and whether it matches the desired keywords

        Returns a tuple with:
        - a boolean, True when the text is different and a keyword matches, False otherwise
        - optionally, the full text difference of the added text
        """

        page_txt = self.get_page(url).replace('\r', '')

        file_path = path + (url.replace("https://", "")).replace("/", "-")
        try:
            with open(file_path, "r") as baseline_file:
                baseline = baseline_file.read()
        except FileNotFoundError:
            baseline = ""

        page_has_diff, page_diff = self.find_text_diff(baseline, page_txt, full_diff)
        self.save_txt_to_file(filepath=file_path, txt=page_txt)

        if page_has_diff:
            if keywords is not None:
                keyword_match = self.find_keywords(
                    input_txt=page_diff, and_operation=keywords['and'], or_operation=keywords.get('or')
                )

                if keyword_match:
                    return True, page_diff

                else:
                    return False, page_diff
            else:
                return True, page_diff

        else:
            return False, None

    def main_differ_page_check(self) -> None:
        """
        Find if there are matching keywords on the text difference (added text only) of a new
        page

        Prints to standard output the results.
        Exits with a failure (code 1) if there's at least one matching difference.
        Exits successfully (code 0) if there are no matching differences.
        """

        config = Config("./swatch-config.json").config_properties

        path = config["store"]["path"]
        page_check = config["watch"]["page_check"]
        diff_log = []

        full_diff = config["notify"]["stdout_full_diff"]

        for page in page_check:
            diff_found, diff = self.page_diffing(
                path=path,
                url=page["url"],
                keywords=page.get("keywords"),
                full_diff=True,
            )

            diff_log.append(
                {page['url']: {"diff_found": diff_found, "diff": diff}}
            )

        for diff in diff_log:
            for key, value in diff.items():

                if full_diff is True:
                    print(f'watching {key}, diff_found: {value["diff_found"]}, diff: {value["diff"]}')
                else:
                    print(f'watching {key}, diff_found: {value["diff_found"]}')

        if any(list(item.values())[0] for item in diff_log):
            exit(1)
        else:
            exit(0)


def sha256sum_of_file(file_path: str):
    """
    Calculate the sha256sum of a file

    Prints result to standard output.

    This hash be used to determine whether a webpage has changed or not.
    """

    # byte chunks
    chunk_size = 4096

    sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as file:
            chunk = file.read(chunk_size)

            while chunk:
                sha256.update(chunk)  # Update the hash object with the chunk
                chunk = file.read(chunk_size)

        checksum = sha256.hexdigest()
    
    except FileNotFoundError:
        checksum = ""

    print(f"{checksum}")


def swatch() -> None:
    """Run site-watchdog application"""

    # Hashing option
    if len(sys.argv) == 3:
        argument = sys.argv[1]
        file_path = sys.argv[2]

        if argument == "hash":
            sha256sum_of_file(file_path)
            return


    diff = Differ().main_differ_page_check()
