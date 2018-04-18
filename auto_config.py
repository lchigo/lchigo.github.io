import os
import time
import uuid
import json


def get_file_update_time(file):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(file)))


def auto_config(article_directory):
    list = []
    articles = {"articles": list}
    for dir in os.listdir(article_directory):
        for f in os.listdir(article_directory+"/"+dir):
            map = {}
            map["id"] = uuid.uuid1().hex
            map["category"] = dir
            map["title"] = f.replace(".md", "")
            map["path"] = article_directory+"/"+dir+"/"+f
            map["date"] = get_file_update_time(article_directory+"/"+dir+"/"+f)
            map["desc"] = ""
            list.append(map)
    list.sort(key=lambda map: map["date"], reverse=True)
    return articles


def write_to_file(content, file):
    with open(file, mode="w", encoding="utf-8") as f:
        f.write(content)


if __name__ == '__main__':
    article_directory = "docs"
    write_to_file(json.dumps(auto_config(article_directory),
                             ensure_ascii=False, indent=4), "config.json")
