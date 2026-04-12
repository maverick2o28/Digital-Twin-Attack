"""
Digital Twin - Raspberry Pi GPIO Controller
Handles LED indicators and buzzer alerts for physical feedback.

Wiring (BCM numbering):
    GPIO 17 → 220Ω → Green  LED → GND   (Normal traffic)
    GPIO 27 → 220Ω → Yellow LED → GND   (Warning / suspicious)
    GPIO 22 → 220Ω → Red    LED → GND   (Active attack)
    GPIO 18 → NPN transistor base → Buzzer 5V → GND

Run standalone for hardware test:
    python3 gpio_controller.py test
"""

import time
import sys
import threading
import json

try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    print("[WARN] RPi.GPIO not found. Running in mock mode.")

# ─── PIN MAP ──────────────────────────────────────────────────────────────────
PIN_LED_GREEN  = 17    # Normal
PIN_LED_YELLOW = 27    # Warning
PIN_LED_RED    = 22    # Attack
PIN_BUZZER     = 18    # Piezo buzzer (active)

ALL_PINS = [PIN_LED_GREEN, PIN_LED_YELLOW, PIN_LED_RED, PIN_BUZZER]

# ─── MOCK GPIO (for non-Pi systems) ───────────────────────────────────────────
class MockGPIO:
    BCM = OUT = HIGH = LOW = IN = 0
    @staticmethod
    def setmode(_): print("[GPIO MOCK] setmode")
    @staticmethod
    def setwarnings(_): pass
    @staticmethod
    def setup(pin, mode): print(f"[GPIO MOCK] setup pin {pin}")
    @staticmethod
    def output(pin, val): print(f"[GPIO MOCK] pin {pin} → {'HIGH' if val else 'LOW'}")
    @staticmethod
    def cleanup(): print("[GPIO MOCK] cleanup")
    @staticmethod
    def input(pin): return 0

if not GPIO_AVAILABLE:
    GPIO = MockGPIO()

# ─── CONTROLLER CLASS ─────────────────────────────────────────────────────────
class GPIOController:
    def __init__(self):
        self._lock = threading.Lock()
        self._buzzer_thread = None
        self._stop_buzzer = threading.Event()
        self.setup()

    def setup(self):
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        for pin in ALL_PINS:
            GPIO.setup(pin, GPIO.OUT)
            GPIO.output(pin, GPIO.LOW)
        self.set_normal()
        print("[GPIO] Controller initialized. Green LED ON.")

    def _all_leds_off(self):
        GPIO.output(PIN_LED_GREEN,  GPIO.LOW)
        GPIO.output(PIN_LED_YELLOW, GPIO.LOW)
        GPIO.output(PIN_LED_RED,    GPIO.LOW)

    def set_normal(self):
        with self._lock:
            self._all_leds_off()
            GPIO.output(PIN_LED_GREEN, GPIO.HIGH)
        print("[GPIO] State → NORMAL (Green)")

    def set_warning(self):
        with self._lock:
            self._all_leds_off()
            GPIO.output(PIN_LED_YELLOW, GPIO.HIGH)
        print("[GPIO] State → WARNING (Yellow)")

    def set_attack(self):
        with self._lock:
            self._all_leds_off()
            GPIO.output(PIN_LED_RED, GPIO.HIGH)
        print("[GPIO] State → ATTACK (Red)")

    def set_state(self, state: str):
        state = state.upper()
        if state in ("NORMAL", "RECOVERY"):
            self.set_normal()
        elif state == "WARNING":
            self.set_warning()
        elif state in ("ATTACK", "UNDER_ATTACK"):
            self.set_attack()

    def buzz(self, duration=0.3, pulses=3, interval=0.1):
        """Non-blocking buzzer in pattern."""
        self._stop_buzzer.clear()
        def _run():
            for _ in range(pulses):
                if self._stop_buzzer.is_set():
                    break
                GPIO.output(PIN_BUZZER, GPIO.HIGH)
                time.sleep(duration)
                GPIO.output(PIN_BUZZER, GPIO.LOW)
                time.sleep(interval)
        self._buzzer_thread = threading.Thread(target=_run, daemon=True)
        self._buzzer_thread.start()

    def buzz_continuous(self, on_time=0.5, off_time=0.5):
        """Continuous buzzer until stop_buzz() is called."""
        self._stop_buzzer.clear()
        def _run():
            while not self._stop_buzzer.is_set():
                GPIO.output(PIN_BUZZER, GPIO.HIGH)
                time.sleep(on_time)
                GPIO.output(PIN_BUZZER, GPIO.LOW)
                time.sleep(off_time)
        self._buzzer_thread = threading.Thread(target=_run, daemon=True)
        self._buzzer_thread.start()

    def stop_buzz(self):
        self._stop_buzzer.set()
        GPIO.output(PIN_BUZZER, GPIO.LOW)

    def flash_attack(self, flashes=6, delay=0.1):
        """Flash red LED rapidly during attack detection."""
        def _flash():
            for _ in range(flashes):
                with self._lock:
                    GPIO.output(PIN_LED_RED, GPIO.HIGH)
                time.sleep(delay)
                with self._lock:
                    GPIO.output(PIN_LED_RED, GPIO.LOW)
                time.sleep(delay)
            with self._lock:
                GPIO.output(PIN_LED_RED, GPIO.HIGH)  # leave on
        t = threading.Thread(target=_flash, daemon=True)
        t.start()

    def hardware_test(self):
        """Cycle all LEDs and buzzer - run at startup to verify wiring."""
        print("[GPIO] Starting hardware self-test...")
        for label, pin in [("GREEN", PIN_LED_GREEN), ("YELLOW", PIN_LED_YELLOW), ("RED", PIN_LED_RED)]:
            print(f"[GPIO] Testing {label} LED (pin {pin})")
            GPIO.output(pin, GPIO.HIGH)
            time.sleep(0.5)
            GPIO.output(pin, GPIO.LOW)
            time.sleep(0.2)
        print("[GPIO] Testing BUZZER (pin {})".format(PIN_BUZZER))
        self.buzz(duration=0.15, pulses=2)
        time.sleep(0.8)
        self.set_normal()
        print("[GPIO] Self-test complete.")

    def cleanup(self):
        self.stop_buzz()
        self._all_leds_off()
        GPIO.cleanup()
        print("[GPIO] Cleanup done.")


# ─── STANDALONE TEST ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    ctrl = GPIOController()
    if "test" in sys.argv:
        ctrl.hardware_test()
        sys.exit(0)

    print("GPIO Controller running. Commands: normal | warning | attack | buzz | test | quit")
    try:
        while True:
            cmd = input("> ").strip().lower()
            if cmd == "normal":   ctrl.set_normal()
            elif cmd == "warning": ctrl.set_warning()
            elif cmd == "attack":
                ctrl.set_attack()
                ctrl.flash_attack()
                ctrl.buzz(duration=0.3, pulses=4)
            elif cmd == "buzz":   ctrl.buzz()
            elif cmd == "test":   ctrl.hardware_test()
            elif cmd == "quit":   break
    finally:
        ctrl.cleanup()
