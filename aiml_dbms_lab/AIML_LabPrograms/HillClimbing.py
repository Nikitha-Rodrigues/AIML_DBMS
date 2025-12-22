import numpy as np

def hill_climbing(function, start_point, step_size=0.01, max_iterations=1000):
    current_position = start_point
    current_value = function(current_position)
    
    for _ in range(max_iterations):
        next_position_up = current_position + step_size
        next_value_up = function(next_position_up)
        
        next_position_down = current_position - step_size
        next_value_down = function(next_position_down)
        
        if next_value_up > current_value and next_value_up >= next_value_down:
            current_position = next_position_up
            current_value = next_value_up
        elif next_value_down > current_value and next_value_down > next_value_up:
            current_position = next_position_down
            current_value = next_value_down
        else:
            break
    
    return current_position, current_value

while True:
    function_str = input("\nEnter a function of x: ")
    try:
        x = 0
        eval(function_str)
        break
    except Exception as error:
        print(f"Invalid function. Please try again. Error: {error}")

function = lambda x: eval(function_str)

while True:
    start_input = input("\nEnter the starting value to begin the search: ")
    try:
        start_point = float(start_input)
        break
    except ValueError:
        print("Invalid input. Please enter a number.")

optimal_x, max_value = hill_climbing(function, start_point)
print(f"The maximum value is found at x = {optimal_x}")
print(f"The maximum function value obtained is {max_value}")