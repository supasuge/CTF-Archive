import socket
import re
import copy
import math
import time

# Configuration for retry mechanism
RECEIVE_RETRIES = 5          # Number of retries for receiving data
RECEIVE_DELAY = 2            # Delay (in seconds) between retries
SEND_RETRIES = 3             # Number of retries for sending data
SEND_DELAY = 1               # Delay (in seconds) between send retries

def receive_data(sock):
    """
    Receive data from the socket until the prompt is reached.
    Implements a retry mechanism to handle temporary network issues.
    """
    retries = 0
    while retries < RECEIVE_RETRIES:
        data = ''
        try:
            while True:
                chunk = sock.recv(4096).decode()
                if not chunk:
                    break
                data += chunk
                if 'Enter command(s)' in data or 'Game Over' in data or 'Congratulations' in data:
                    break
            if data:
                return data
            else:
                raise socket.timeout
        except socket.timeout:
            retries += 1
            print(f"Receive timeout. Retrying {retries}/{RECEIVE_RETRIES}...")
            time.sleep(RECEIVE_DELAY)
    print("Failed to receive data after multiple attempts.")
    return None

def parse_board(output_lines):
    """Parse the game board from the output lines."""
    board = []
    for line in output_lines:
        # Match lines that contain the board numbers
        match = re.match(r'\s*(\d+|0)\s+(\d+|0)\s+(\d+|0)\s+(\d+|0)', line)
        if match:
            row = []
            for num in match.groups():
                row.append(int(num))
            board.append(row)
    return board

def simulate_move(board, move):
    """Simulate the move and return the new board state."""
    new_board = [row.copy() for row in board]
    if move == 'w':
        new_board = move_up(new_board)
    elif move == 'a':
        new_board = move_left(new_board)
    elif move == 's':
        new_board = move_down(new_board)
    elif move == 'd':
        new_board = move_right(new_board)
    else:
        return None
    return new_board

def is_valid_move(board, move):
    """Check if making the move changes the board state."""
    new_board = simulate_move(board, move)
    return new_board != board

def decide_move(board):
    """Decide the next move based on the board state using Expectimax."""
    moves = ['w', 'a', 's', 'd']
    best_move = None
    best_score = -math.inf
    depth = 3  # Adjust the depth based on performance

    for move in moves:
        if is_valid_move(board, move):
            new_board = simulate_move(board, move)
            score = expectimax(new_board, depth - 1, True)
            if score > best_score:
                best_score = score
                best_move = move

    return best_move if best_move else 'q'

def expectimax(board, depth, is_chance):
    if depth == 0 or is_game_over(board):
        return evaluate_board(board)
    
    if is_chance:
        empty = get_empty_cells(board)
        if not empty:
            return evaluate_board(board)
        expected_value = 0
        probability_per_cell = 1 / len(empty)
        for cell in empty:
            for tile, prob in [(2, 0.9), (4, 0.1)]:
                new_board = add_tile(copy.deepcopy(board), cell, tile)
                score = expectimax(new_board, depth - 1, False)
                expected_value += prob * (score * probability_per_cell)
        return expected_value
    else:
        max_score = -math.inf
        for move in ['w', 'a', 's', 'd']:
            new_board = simulate_move(copy.deepcopy(board), move)
            if new_board != board:
                score = expectimax(new_board, depth - 1, True)
                if score > max_score:
                    max_score = score
        return max_score if max_score != -math.inf else evaluate_board(board)

def is_game_over(board):
    """Check if no moves are possible."""
    for move in ['w', 'a', 's', 'd']:
        if simulate_move(copy.deepcopy(board), move) != board:
            return False
    return True

def get_empty_cells(board):
    """Return a list of empty cells as (row, col) tuples."""
    empty = []
    for i in range(len(board)):
        for j in range(len(board[0])):
            if board[i][j] == 0:
                empty.append((i, j))
    return empty

def add_tile(board, cell, tile):
    """Add a tile (2 or 4) to the specified cell."""
    row, col = cell
    board[row][col] = tile
    return board

def move_left(board):
    size = len(board)
    for row in board:
        original = row.copy()
        # Slide tiles to the left
        tiles = [num for num in row if num != 0]
        new_row = []
        skip = False
        for i in range(len(tiles)):
            if skip:
                skip = False
                continue
            if i + 1 < len(tiles) and tiles[i] == tiles[i + 1]:
                new_row.append(tiles[i] * 2)
                skip = True
            else:
                new_row.append(tiles[i])
        # Fill the remaining cells with zeros
        new_row += [0] * (size - len(new_row))
        row[:] = new_row
    return board

def move_right(board):
    size = len(board)
    for row in board:
        original = row.copy()
        # Slide tiles to the right
        tiles = [num for num in row if num != 0]
        new_row = []
        skip = False
        i = len(tiles) - 1
        while i >= 0:
            if skip:
                skip = False
                i -= 1
                continue
            if i - 1 >= 0 and tiles[i] == tiles[i - 1]:
                new_row.insert(0, tiles[i] * 2)
                skip = True
            else:
                new_row.insert(0, tiles[i])
            i -= 1
        # Fill the remaining cells with zeros
        new_row = [0] * (size - len(new_row)) + new_row
        row[:] = new_row
    return board

def move_up(board):
    size = len(board)
    for col in range(size):
        original_col = [board[row][col] for row in range(size)]
        # Slide tiles up
        tiles = [num for num in original_col if num != 0]
        new_col = []
        skip = False
        for i in range(len(tiles)):
            if skip:
                skip = False
                continue
            if i + 1 < len(tiles) and tiles[i] == tiles[i + 1]:
                new_col.append(tiles[i] * 2)
                skip = True
            else:
                new_col.append(tiles[i])
        # Fill the remaining cells with zeros
        new_col += [0] * (size - len(new_col))
        # Update the board
        for row in range(size):
            board[row][col] = new_col[row]
    return board

def move_down(board):
    size = len(board)
    for col in range(size):
        original_col = [board[row][col] for row in range(size)]
        # Slide tiles down
        tiles = [num for num in original_col if num != 0]
        new_col = []
        skip = False
        i = len(tiles) - 1
        while i >= 0:
            if skip:
                skip = False
                i -= 1
                continue
            if i - 1 >= 0 and tiles[i] == tiles[i - 1]:
                new_col.insert(0, tiles[i] * 2)
                skip = True
            else:
                new_col.insert(0, tiles[i])
            i -= 1
        # Fill the remaining cells with zeros
        new_col = [0] * (size - len(new_col)) + new_col
        # Update the board
        for row in range(size):
            board[row][col] = new_col[row]
    return board

def evaluate_board(board):
    """Evaluate the board and return a score based on heuristics."""
    empty_tiles = sum(row.count(0) for row in board)
    max_tile = max(max(row) for row in board)
    monotonicity_score = calculate_monotonicity(board)
    smoothness_score = calculate_smoothness(board)
    merge_potential = calculate_merge_potential(board)
    
    # Weight the heuristics
    score = (
        empty_tiles * 1000 +       # Prioritize empty tiles
        max_tile * 10 +            # Encourage higher max tiles
        monotonicity_score * 1 +   # Encourage monotonic rows/columns
        smoothness_score * -1 +    # Penalize abrupt changes
        merge_potential * 100      # Encourage merging opportunities
    )
    return score

def calculate_monotonicity(board):
    """Calculate monotonicity of the board."""
    total = 0
    for row in board:
        total += is_monotonic(row)
    for col in zip(*board):
        total += is_monotonic(col)
    return total

def is_monotonic(line):
    """Check if a line (row or column) is monotonic."""
    line = [num for num in line if num != 0]
    if len(line) <= 1:
        return 1
    incre = all(x <= y for x, y in zip(line, line[1:]))
    decre = all(x >= y for x, y in zip(line, line[1:]))
    return int(incre or decre)

def calculate_smoothness(board):
    """Calculate smoothness of the board (penalize large differences between adjacent tiles)."""
    smoothness = 0
    size = len(board)
    for i in range(size):
        for j in range(size):
            if board[i][j] != 0:
                value = board[i][j]
                # Check right neighbor
                if j + 1 < size and board[i][j + 1] != 0:
                    smoothness += abs(value - board[i][j + 1])
                # Check bottom neighbor
                if i + 1 < size and board[i + 1][j] != 0:
                    smoothness += abs(value - board[i + 1][j])
    return smoothness

def calculate_merge_potential(board):
    """Calculate potential merges available."""
    merges = 0
    size = len(board)
    for i in range(size):
        for j in range(size - 1):
            if board[i][j] != 0 and board[i][j] == board[i][j + 1]:
                merges += 1
    for j in range(size):
        for i in range(size - 1):
            if board[i][j] != 0 and board[i][j] == board[i + 1][j]:
                merges += 1
    return merges

def main():
    HOST = '54.85.45.101'  
    PORT = 8006             

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.settimeout(2.0)  # Set a timeout for socket operations
    except socket.error as e:
        print(f"Socket error during connection: {e}")
        return

    while True:
        data = receive_data(s)
        if not data:
            print("No data received. Possible network issue. Retrying...")
            continue 

        # Print the game output for debugging
        print(data)

        if 'Game Over' in data or 'Congratulations' in data:
            print(data)
            break

        output_lines = data.split('\n')
        board = parse_board(output_lines)

        if not board or len(board) != 4:
            print("Invalid board received. Skipping move.")
            continue

        move = decide_move(board)
        print(f"Decided move: {move}")  # For debugging

        if move == 'q':
            print("No valid moves left or no suitable move found. Exiting.")
            break

        send_success = send_move_with_retry(s, move)
        if not send_success:
            print("Failed to send move after multiple attempts. Exiting.")
            break

    s.close()

def send_move_with_retry(sock, move):
    """
    Send the chosen move to the server with a retry mechanism.
    Returns True if the move was sent successfully, False otherwise.
    """
    retries = 0
    while retries < SEND_RETRIES:
        try:
            sock.sendall((move + '\n').encode())
            return True
        except socket.error as e:
            retries += 1
            print(f"Send error: {e}. Retrying {retries}/{SEND_RETRIES}...")
            time.sleep(SEND_DELAY)
    return False

if __name__ == "__main__":
    main()
