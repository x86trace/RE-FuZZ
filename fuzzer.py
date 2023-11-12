from urllib.parse import urlparse
import requests
import os
import sys
import argparse
from fake_useragent import UserAgent

some_info = """
\u001b[32;1m- open redirect tool \u001b[0m
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

\u001b[34;1m usage:
   >>> python3 open-re.py -u [URL] -lp [payload]
   >>> python3 open-re.py -lu [file] -lp [payloads]\u001b[0m  

\u001b[31;1m:copyright: (c) 2021 by 0xtrace.
:license: Apache 2.0, see LICENSE for more details.\u001b[0m
"""


def usage() -> None:
    print(
        """
   + ======================================================================= +
    \u001b[31;1m: ERR_ARGUMENT_PARSE THIS MEESAGE PRINTING WHEN ERROR USE FOR TOOL \u001b[0m              
   +=========================================================================+
        """
    )


def get_keyword(url: str) -> str:
    parsed_url = urlparse(url)
    query = parsed_url.query
    symbol = query.find('=')
    keyword_listed = []
    keyword = ''

    for j in range(0, symbol):
        keyword_listed.append(query[j])

    keyword = keyword.join(keyword_listed)

    return keyword


def validate_url(url: str) -> bool:
    parsed_url = urlparse(url)

    if not get_keyword(url) or not parsed_url.scheme or not parsed_url.netloc:
        print('Error: ERR_ARGUMENT This Message display when wrong URL passed ...')
        return False

    return True


def add_payload_to_url(url: str, payload: str) -> str:
    try:
        if validate_url(url):
            symbol = url.find('=')
            target_url = url[:symbol + 1]
            final_url = f'{target_url}{payload}'
            return final_url
    except:
        pass


def is_open_re(url: str) -> bool:
    user_agent = UserAgent()
    headers = {'User-Agent': user_agent.random}

    try:
        response = requests.get(url, headers=headers)

        if 300 <= response.status_code < 400:
            if response.headers.get('Location') == url:
                return True

    except:
        print("ERR_NETWORK : THIS MESSAGE passed when fail to fetch URL so maybe wrong URL or fail to fetch URL")
        pass

    return False


def fuzzer_one_url(url: str, file_param: str) -> list:
    list_of_vuln_url = []
    try:
        with open(file_param, 'r') as file:
            list_of_payloads = file.readlines()

            for payload in list_of_payloads:
                target = add_payload_to_url(url, payload)

                if '-d' or '--debug' in sys.argv:
                    print(f'target URL We are testing : {target}')

                if is_open_re(target):
                    list_of_vuln_url.append(target)

    except FileNotFoundError as error:
        print(f'Error: {error}')
    except IOError as error:
        print(f'Error: {error} ')
    return list_of_vuln_url


def fuzzing_list_url(file_url: str, file_payload: str) -> list:
    result_list = []
    try:
        with open(file_url, 'r') as file:
            list_of_urls = file.readlines()

            for url in list_of_urls:
                list_of_vuln_urls = fuzzer_one_url(url, file_payload)

                for vuln_url in list_of_vuln_urls:
                    result_list.append(vuln_url)
    except:
        pass

    return result_list


def output_in_file(list_of_data: list) -> None:
    with open('output_file.txt', 'a') as open_file:
        open_file.writelines(list_of_data)


def output_on_screen(list_of_urls: list) -> None:
    print('\n \n this Targets maybe infected in Own URL:')
    for url in list_of_urls:
        print(url)


def main():
    parser = argparse.ArgumentParser(description="Open-re: A tool to test open redirects vuln")
    parser.add_argument('-u', '--url', help='URL of your target to be tested')
    parser.add_argument('-lu', '--list-urls', help='file of URLs with parameters to test')
    parser.add_argument('-lp', '--list-payloads', help='list of payloads [file] it\'s default fuzz.txt', default='fuzz.txt')
    parser.add_argument('-d', '--debug', help='display printing of what you are testing', required=False, )
    parser.add_argument('-o', '--output-file', help='output file containing result of scanning', required=False)
    args = parser.parse_args()

    if args.url and args.list_payloads:
        if not os.path.isfile(args.list_payloads) and not os.access(args.list_payloads, os.R_OK):
            print(f'[-] {args.list_payloads} does not exist.')
            sys.exit()

        list_vuln_url = fuzzer_one_url(args.url, args.list_payloads)

        if '-o' or '--output' in sys.argv and list_vuln_url:
            output_in_file(list_vuln_url)

        if list_vuln_url:
            output_on_screen(list_vuln_url)
        else:
            print('No URL infected. Maybe you can try different payloads or maybe our tool failed to handle something.')

    if args.list_urls and args.list_payloads:
        if not os.path.isfile(args.list_urls) and not os.path.isfile(args.list_payloads):
            print(f'[-] {args.list_payloads} does not exist.')
            sys.exit()

        list_vuln_urls = fuzzing_list_url(args.list_urls, args.list_payloads)

        if '-o' or '--output' in sys.argv and list_vuln_urls:
            output_in_file(list_vuln_urls)

        if list_vuln_urls:
            output_on_screen(list_vuln_urls)
        else:
            print('No URL infected. Maybe you can try different payloads or maybe our tool failed to handle something.')


if __name__ == '__main__':
    banner = """
┳┓┏┓  ┏┓  ┏┓┏┓
┣┫┣ ━━┣ ┓┏┏┛┏┛
┛┗┗┛  ┻ ┗┻┗┛┗┛
    \u001b[32;1m- By Trace \u001b[0m
    """
    print(some_info)
    print(banner)

    main()
