import azure.functions as func
from main import run

def main(mytimer: func.TimerRequest) -> None:
    run()
