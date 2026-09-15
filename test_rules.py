from rules import run_analysis

result = run_analysis("Dear Customer, verify your OTP immediately!!!", "http://192.168.1.1@login.com")
print(result["score"], result["risk"])