import queue
import pygame
import sys
from pygame.color import THECOLORS
import math
import main
import threading
import os

pygame.init()

color_ac = pygame.Color('black')
color_pc = pygame.Color('white')
current_file_path = os.path.abspath(__file__)
current_directory_path = os.path.dirname(current_file_path)


screen = pygame.display.set_mode((1200, 800))
screen.fill((0, 0, 0))

pygame.display.set_caption('Server scanner')

pygame.display.flip()

user_text = ""
active = False
animation_active = False
run_scan = False
end_scan = False
color = color_pc

background_color = (0, 0, 0)
circle_color = (255, 255, 255)
circle_center = (600, 400)
circle_radius = 35
dot_radius = 2
num_dots = 20
angle_step = 360 / num_dots
rotation_speed = 2

angle = 0
input_rect = pygame.Rect(250, 250, 700, 50)
font = pygame.font.SysFont('Helvetica', 36)

button_rect_open = pygame.Rect(500, 400, 200, 50)
button_rect_restart = pygame.Rect(500, 460, 200, 50)
button_text_open = "Open File"
button_text_restart = "Restart"

file_path = current_directory_path + f'/result.txt'

clock = pygame.time.Clock()
result_queue = queue.Queue()

def draw_centered_text(surface, text, rect, font, color):
    text_surface = font.render(text, True, color)
    text_rect = text_surface.get_rect(center=rect.center)
    surface.blit(text_surface, text_rect)

def run_scan_in_thread(url, queue):
    result = main.main(url)
    queue.put(result)

def draw_button(surface, rect, text, font, color):
    pygame.draw.rect(surface, color, rect)
    draw_centered_text(surface, text, rect, font, pygame.Color('black'))

def open_file():
    os.system(f'xdg-open "{file_path}"')  # Для Linux, замените на соответствующую команду для вашей ОС

def restart_program():
    global user_text, active, animation_active, run_scan, end_scan, angle
    user_text = ""
    active = False
    animation_active = False
    run_scan = False
    end_scan = False
    angle = 0
    screen.fill((0, 0, 0))


def update_screen():
    screen.fill((0, 0, 0))
    pygame.draw.rect(screen, color, input_rect, 2)
    prompt_text = "Enter URL of web-page:"
    draw_centered_text(screen, prompt_text, pygame.Rect(420, 100, 360, 50), font, (255, 255, 255))
    draw_centered_text(screen, user_text, input_rect, font, (255, 255, 255))
    input_rect.w = max(700, font.render(user_text, True, (255, 255, 255)).get_width() + 10)

    if animation_active:
        for i in range(num_dots):
            dot_angle = math.radians(angle + i * angle_step)
            dot_x = circle_center[0] + circle_radius * math.cos(dot_angle)
            dot_y = circle_center[1] + circle_radius * math.sin(dot_angle)
            pygame.draw.circle(screen, circle_color, (int(dot_x), int(dot_y)), dot_radius)
    
    if end_scan:
        result_text = f"Scan results saved to file: {file_name}"
        draw_centered_text(screen, result_text, pygame.Rect(400, 310, 360, 50), font, (255, 255, 255))
        draw_button(screen, button_rect_open, button_text_open, font, pygame.Color('white'))
        draw_button(screen, button_rect_restart, button_text_restart, font, pygame.Color('white'))

    pygame.display.update()

while True:
    for events in pygame.event.get():
        if events.type == pygame.QUIT:
            pygame.quit()
            sys.exit()

        if events.type == pygame.MOUSEBUTTONDOWN:
            if input_rect.collidepoint(events.pos):
                active = True
            elif end_scan:
                if button_rect_open.collidepoint(events.pos):
                    open_file()
                elif button_rect_restart.collidepoint(events.pos):
                    restart_program()

        if events.type == pygame.KEYDOWN:
            if active:
                if events.key == pygame.K_BACKSPACE:
                    user_text = user_text[:-1]
                elif events.key == pygame.K_RETURN:
                    print(user_text)
                    animation_active = True
                    file_name = 'result.txt'
                    scan_thread = threading.Thread(target=run_scan_in_thread, args=(user_text, result_queue))
                    scan_thread.start()
                else:
                    user_text += events.unicode

    if active:
        color = color_ac
    else:
        color = color_pc

    if animation_active:
        angle = (angle + rotation_speed) % 360

    if not result_queue.empty():
        end_scan = result_queue.get()
        animation_active = False  # Остановка анимации

    update_screen()
    clock.tick(60)
