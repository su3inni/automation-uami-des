import azure.functions as func
from .des_uami_checker import run

def main(mytimer: func.TimerRequest):
    run()
