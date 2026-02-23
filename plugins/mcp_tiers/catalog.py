# get code scanned and get num of low, medium and high errors

import datetime
from fileinput import fileno
import uuid




class catalog():

  
  def __init__(self, name : str = "", version : str = "", source_type : str = "", checked : datetime.datetime = None):
    self.id = uuid.uuid4()
    self.name = name 
    self.version = version
    self.source_type = source_type
    self.last_checked = checked
    self.last_updated = datetime.datetime.now()
    self.score = self.trust_score()
    self.trust_tier = self.assign_tier()
  
  def trust_tiers(self,tier) -> dict[str]:

    tiers = {

      verified := {
        min_score := 90,
        badge_color:= "#22c55e",    # green
        badge_icon:= "shield-check",
        requires_manual_review:= True,
        verification_expiry_days:= 90
      },
        
      standard := {
        min_score:= 70,
        badge_color:= "#3b82f6",    # blue
        badge_icon:= "shield"
      },
        
      community := {
        min_score:= 50,
        badge_color:= "#eab308",    # yellow
        badge_icon:= "shield-question"
      },

      untrusted := {
        min_score := float('-inf'),   # added just in case it is being checked it will always qualify it in untrusted
        badge_color := "#ef4444",   # red
        badge_icon := "shield-x",
        requires_approval := True,
        warning_message := "This server has not been security verified"
      }
    }
  
  # Catalog display settings
  def display(self,export : bool = False):

    settings = {  
      show_trust_score := True,
      show_vulnerability_summary := True,
      show_last_assessed := True,
      show_sbom_indicator := True,
      default_sort := "trust_score_desc"
    }

    for setting in settings:
        print(setting)

    if export:
      #TODO: implement export functionality
      export()
    else:
      pass
    
    
  #TODO Export settings
  def export(self):
    formats = ["csv", "json", "pdf"]
    include_security_metadata = True

  
  # a function that calculates a trust score
  # input:
  #   
  def trust_score(self, errors : list[int,int,int] = [-1, -1, -1]) -> int:
    if errors[0] == errors[1] == errors[2] == -1:
      print("bad")
      return -1
    else:
      return 100 - (errors[0] * 50) - (errors[1] * 20) - (errors[2] * 5) - ((datetime.datetime.now() - self.last_updated).days * 1)

  # Scanning and returning the errors in a list of critical
  def scanning(self, file : fileno = None) -> list[int,int,int]:
    if file == None:
      return [-1,-1,-1]
    else:
      #TODO add scanner that returns the 3 error types
      return[0,0,0]
    
  def assign_tier(self):
    if self.score >= self.trust_tiers("verified")["min_score"] and (datetime.datetime.now() - self.last_checked).days <= 90 and self.last_checked != None:
      return "verified"
    elif self.score >= self.trust_tiers("standard")["min_score"]:
      return "standard"
    elif self.score >= self.trust_tiers("community")["min_score"]:
      return "community"
    else:
      return "untrusted"