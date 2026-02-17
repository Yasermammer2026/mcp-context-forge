#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./plugins/source_scanner/report.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Author: Yanko

Generates a report from the scanner json files
"""
#from plugins.source_scanner.parsing.normalizer import Normalizer
import json
from typing import Any


class report:
    def __init__(self, report_path: str, filename: str, scanner: str):
        self.report_path = report_path
        self.filename = filename
        self.scanner = scanner
        self.data: list[Any] = []
        self.load()

    def load(self):
        with open(self.report_path, 'r') as file:
            self.data = json.load(file)
        return self.data
    
    
    def summary(self) -> dict[str, int]:
        levels = {"HIGH" : 0, "MEDIUM" : 0, "LOW" : 0}

        for file in self.data:
            levels[file["severity"]] += 1


        summary = {
            "total_files" : len(self.data),
            "total_issues" : (levels["HIGH"] + levels["MEDIUM"] + levels["LOW"]),
            "HIGH" : levels["HIGH"],
            "MEDIUM" : levels["MEDIUM"],
            "LOW" : levels["LOW"]
        }
        return summary
    
    def ordered(self) -> dict[str, dict[str, int]]:
        ordered: dict[str, dict[str, int]] = { "HIGH" : {}, "MEDIUM" : {}, "LOW" : {} }

        for file in self.data:
            if file["issue"] not in ordered[file["severity"]]:
                ordered[file["severity"]][file["issue"]] = 1
            else:
                ordered[file["severity"]][file["issue"]] += 1
        return ordered
    
    
        

