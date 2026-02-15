#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./plugins/source_scanner/report.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Author: Yanko

Generates a report from the scanner json files
"""
import json
from typing import Any


class report:
    def __init__(self, report_path: str, filename: str):
        self.report_path = report_path
        self.data: list[Any] = []

    def load(self):
        with open(self.report_path, 'r') as file:
            self.data = json.load(file)

    def get_data(self) -> list[Any]:
        if self.data == []:
            self.load()
        return self.data
    
    def Summary(self) -> dict[str, int]:
        data = self.get_data()
        levels = {"HIGH" : 0, "MEDIUM" : 0, "LOW" : 0}

        for file in data:
            levels[file["severity"]] += 1


        summary = {
            "total_files" : len(data),
            "total_issues" : (levels["HIGH"] + levels["MEDIUM"] + levels["LOW"]),
            "HIGH" : levels["HIGH"],
            "MEDIUM" : levels["MEDIUM"],
            "LOW" : levels["LOW"]
        }
        return summary
        

