import tkinter as tk
from tkinter import ttk, scrolledtext
import paramiko
import os
import threading
import queue
import uuid
import re
import json
import time

# --- CONFIGURACIÓN ---
# ¡IMPORTANTE! Modifica estas variables según tu proyecto.
REPO_URL = "https://github.com/sisoputnfrba/tp-2025-1c-BugBusters"  # URL de tu repositorio Git
PROJECT_DIR_NAME = "tp-2025-1c-BugBusters"  # Nombre de la carpeta que se crea al clonar
CONFIGS_BASE_PATH = "configs"  # Ruta local a la carpeta que contiene las configuraciones de prueba
TEST_CONFIG_FILE = "pruebas.json" # Archivo de configuración de pruebas
PRUEBAS_REPO_URL = "https://github.com/sisoputnfrba/revenge-of-the-cth-pruebas" # Repositorio con pseudocódigos
PRUEBAS_REPO_PATH = "/home/utnso/revenge-of-the-cth-pruebas" # Directorio de destino para el repo de pruebas
COMMONS_REPO_URL = "https://github.com/sisoputnfrba/so-commons-library"

class TestAutomationGUI(tk.Tk):
    """
    Clase principal para la interfaz gráfica de automatización de pruebas.
    """
    def __init__(self):
        super().__init__()
        self.title("Automatizador de Pruebas v3.11")
        self.geometry("800x850")
        self.minsize(600, 500)  # Tamaño mínimo de la ventana
        
        # Hacer la ventana redimensionable
        self.resizable(True, True)
        
        # Configurar el grid para que se expanda
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.module_entries = {}
        self.saved_ips = {}
        self.log_queue = queue.Queue()
        self.running_machines = {}
        self.TESTS_CONFIG = {}

        # Estilo
        style = ttk.Style(self)
        style.theme_use("clam")

        self.create_widgets()
        self.setup_log_colors()
        self.load_tests_config() # Carga inicial de pruebas
        self.process_log_queue()

    def load_secrets(self):
        """Carga las credenciales desde secrets.json si existe."""
        secrets_path = os.path.join(os.path.dirname(__file__), "secrets.json")
        if os.path.exists(secrets_path):
            try:
                with open(secrets_path, "r") as f:
                    secrets = json.load(f)
                    self.github_user_entry.delete(0, tk.END)
                    self.github_user_entry.insert(0, secrets.get("github_user", ""))
                    self.github_token_entry.delete(0, tk.END)
                    self.github_token_entry.insert(0, secrets.get("github_token", ""))
                    self.ssh_user_entry.delete(0, tk.END)
                    self.ssh_user_entry.insert(0, secrets.get("ssh_user", ""))
                    self.ssh_password_entry.delete(0, tk.END)
                    self.ssh_password_entry.insert(0, secrets.get("ssh_password", ""))

            except Exception as e:
                self.log_to_console(f"Error al cargar secrets.json: {e}", level="error")

    def create_widgets(self):
        """Crea todos los widgets de la interfaz gráfica."""
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Frame superior para toda la configuración ---
        # Crear un frame con canvas y scrollbar para el contenido scrolleable
        settings_container = ttk.Frame(main_frame)
        settings_container.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
        
        # Canvas para scroll
        canvas = tk.Canvas(settings_container)
        scrollbar = ttk.Scrollbar(settings_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Configurar scroll con rueda del mouse
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)
        
        # Configurar el ancho del frame interno para que coincida con el canvas
        def configure_scroll_region(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas_width = canvas.winfo_width()
            if canvas_width > 1:  # Solo configurar si el canvas tiene un ancho válido
                window_items = canvas.find_all()
                if window_items:  # Solo configurar si hay elementos en el canvas
                    canvas.itemconfig(window_items[0], width=canvas_width - 4)  # -4 para margen
        
        canvas.bind('<Configure>', configure_scroll_region)
        
        # También vincular el evento de redimensionamiento del frame scrollable
        def on_frame_configure(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        scrollable_frame.bind('<Configure>', on_frame_configure)


        # --- Contenido dentro del frame con scroll ---
        repo_credentials_frame = ttk.LabelFrame(scrollable_frame, text="Credenciales de Repositorio (GitHub)", padding="10")
        repo_credentials_frame.pack(fill=tk.X, pady=5, padx=5)

        ttk.Label(repo_credentials_frame, text="Usuario GitHub:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.github_user_entry = ttk.Entry(repo_credentials_frame, width=30)
        self.github_user_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(repo_credentials_frame, text="Token de Acceso:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.github_token_entry = ttk.Entry(repo_credentials_frame, show="*", width=30)
        self.github_token_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        repo_credentials_frame.columnconfigure(1, weight=1)

        credentials_frame = ttk.LabelFrame(scrollable_frame, text="Credenciales SSH", padding="10")
        credentials_frame.pack(fill=tk.X, pady=5, padx=5)

        ttk.Label(credentials_frame, text="Usuario SSH:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ssh_user_entry = ttk.Entry(credentials_frame, width=30)
        self.ssh_user_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(credentials_frame, text="Contraseña SSH:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ssh_password_entry = ttk.Entry(credentials_frame, show="*", width=30)
        self.ssh_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        credentials_frame.columnconfigure(1, weight=1)

        test_selection_frame = ttk.LabelFrame(scrollable_frame, text="Configuración de Prueba", padding="10")
        test_selection_frame.pack(fill=tk.X, pady=5, padx=5)
        
        selector_frame = ttk.Frame(test_selection_frame)
        selector_frame.pack(fill=tk.X)
        selector_frame.columnconfigure(0, weight=1)

        self.test_var = tk.StringVar()
        self.test_selector = ttk.Combobox(selector_frame, textvariable=self.test_var, state="readonly")
        self.test_selector.grid(row=0, column=0, sticky="ew", pady=5)
        self.test_selector.bind("<<ComboboxSelected>>", self.on_test_select)

        self.reload_button = ttk.Button(selector_frame, text="Recargar Pruebas", command=self.load_tests_config)
        self.reload_button.grid(row=0, column=1, padx=(10, 0), pady=5)

        self.modules_frame = ttk.Frame(test_selection_frame, padding="5")
        self.modules_frame.pack(fill=tk.X, pady=5)

        control_frame = ttk.Frame(scrollable_frame)
        control_frame.pack(fill=tk.X, pady=10, padx=5)
        control_frame.columnconfigure(0, weight=1)
        control_frame.columnconfigure(1, weight=1)
        
        self.run_button = ttk.Button(control_frame, text="Preparar Despliegue", command=self.start_deployment_thread)
        self.run_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        
        self.stop_button = ttk.Button(control_frame, text="Detener Ejecución", command=self.start_stop_thread, state="disabled")
        self.stop_button.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        # --- Consola de Salida ---
        log_frame = ttk.LabelFrame(main_frame, text="Consola de Salida", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10, side=tk.BOTTOM)
        
        self.log_console_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state="disabled", bg="black", fg="white", font=("monospace", 9))
        self.log_console_widget.pack(fill=tk.BOTH, expand=True)
        self.load_secrets()
    
    def setup_log_colors(self):
        """Define los tags de color para la consola."""
        self.log_console_widget.tag_config("title", foreground="#00FFFF", font=("monospace", 9, "bold")) # Cian
        self.log_console_widget.tag_config("info", foreground="white")
        self.log_console_widget.tag_config("command", foreground="gray70")
        self.log_console_widget.tag_config("success", foreground="#32CD32") # Verde Lima
        self.log_console_widget.tag_config("warning", foreground="yellow")
        self.log_console_widget.tag_config("error", foreground="#FF4500") # Rojo anaranjado

    def load_tests_config(self):
        """Carga la configuración de las pruebas desde el archivo JSON."""
        try:
            with open(TEST_CONFIG_FILE, 'r') as f:
                self.TESTS_CONFIG = json.load(f)
            self.test_selector['values'] = list(self.TESTS_CONFIG.keys())
            self.test_var.set("") # Limpiar selección
            for widget in self.modules_frame.winfo_children():
                widget.destroy()
            self.module_entries.clear()
            self.log_to_console(f"Configuración de pruebas cargada/recargada desde '{TEST_CONFIG_FILE}'.", level="success")
        except FileNotFoundError:
            self.log_to_console(f"Error: No se encontró el archivo '{TEST_CONFIG_FILE}'.", level="error")
            self.TESTS_CONFIG = {}
            self.test_selector['values'] = []
        except json.JSONDecodeError:
            self.log_to_console(f"Error: El archivo '{TEST_CONFIG_FILE}' tiene un formato JSON inválido.", level="error")
            self.TESTS_CONFIG = {}
            self.test_selector['values'] = []

    def on_test_select(self, event=None):
        """Genera los campos de entrada para IPs y parámetros basado en la prueba seleccionada."""
        for module_name, entry_dict in self.module_entries.items():
            ip = entry_dict['ip'].get()
            if ip:
                self.saved_ips[module_name] = ip

        for widget in self.modules_frame.winfo_children():
            widget.destroy()
        self.module_entries.clear()

        test_name = self.test_var.get()
        if not test_name: return

        modules = self.TESTS_CONFIG[test_name]["modules"]
        self.log_to_console(f"Configurando IPs para la prueba: '{test_name}'\n", level="title")

        row_counter = 0
        for module, count in modules.items():
            for i in range(1, count + 1):
                if (module == "cpu" or module == "io") and count == 1:
                    module_instance_name = f"{module}1"
                else:
                    module_instance_name = f"{module}" if count == 1 else f"{module}{i}"
                
                ttk.Label(self.modules_frame, text=f"IP para {module_instance_name}:").grid(row=row_counter, column=0, padx=5, pady=2, sticky="w")
                ip_entry = ttk.Entry(self.modules_frame, width=30)
                ip_entry.grid(row=row_counter, column=1, padx=5, pady=2, sticky="ew")
                self.module_entries[module_instance_name] = {'ip': ip_entry}

                # Restaura la IP si existe
                if module_instance_name in self.saved_ips:
                    ip_entry.insert(0, self.saved_ips[module_instance_name])
                self.module_entries[module_instance_name] = {'ip': ip_entry}

                if module == "io":
                    ttk.Label(self.modules_frame, text="Tipo:").grid(row=row_counter, column=2, padx=5, pady=2, sticky="w")
                    type_entry = ttk.Entry(self.modules_frame, width=15)
                    type_entry.grid(row=row_counter, column=3, padx=5, pady=2, sticky="ew")
                    type_entry.insert(0, "DISCO")
                    self.module_entries[module_instance_name]['type'] = type_entry

                row_counter += 1
        
        self.modules_frame.columnconfigure(1, weight=2)
        self.modules_frame.columnconfigure(3, weight=1)

    def log_to_console(self, message, level="info"):
        """Añade un mensaje con un nivel a la cola para ser mostrado en la consola."""
        self.log_queue.put((message, level))

    def process_log_queue(self):
        """Procesa la cola de mensajes y los muestra en la GUI con su color correspondiente."""
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self.log_console_widget.config(state="normal")
                self.log_console_widget.insert(tk.END, message + "\n", level)
                self.log_console_widget.config(state="disabled")
                self.log_console_widget.see(tk.END)
        except queue.Empty:
            pass
        self.after(100, self.process_log_queue)

    def start_deployment_thread(self):
        """Inicia el proceso de despliegue en un hilo separado para no congelar la GUI."""
        self.run_button.config(state="disabled")
        self.stop_button.config(state="disabled")
        self.log_to_console("--- INICIANDO PREPARACIÓN DE MÓDULOS ---", level="title")
        
        deployment_thread = threading.Thread(target=self.run_deployment, daemon=True)
        deployment_thread.start()

    def run_deployment(self):
        """Lógica principal del despliegue que se ejecuta en el hilo secundario."""
        github_user = self.github_user_entry.get()
        github_token = self.github_token_entry.get()
        ssh_user = self.ssh_user_entry.get()
        ssh_password = self.ssh_password_entry.get()
        test_name = self.test_var.get()

        if not all([github_user, github_token, ssh_user, ssh_password, test_name]):
            self.log_to_console("Error: Por favor, completa todos los campos de credenciales y selecciona una prueba.", level="error")
            self.run_button.config(state="normal")
            return
        
        repo_url_with_auth = REPO_URL.replace("https://", f"https://{github_user}:{github_token}@")

        ip_map = {}
        for module_name, entries in self.module_entries.items():
            ip = entries['ip'].get()
            if not ip:
                self.log_to_console(f"Error: La IP para {module_name} no puede estar vacía.", level="error")
                self.run_button.config(state="normal")
                return
            ip_map[module_name] = ip
        
        machines = {}
        for module_name, entries in self.module_entries.items():
            machine_info = {"ip": ip_map[module_name], "username": ssh_user, "password": ssh_password}
            if 'type' in entries:
                io_type = entries['type'].get()
                if not io_type:
                    self.log_to_console(f"Error: El tipo para {module_name} no puede estar vacío.", level="error")
                    self.run_button.config(state="normal")
                    return
                machine_info['io_type'] = io_type
            machines[module_name] = machine_info
        
        self.running_machines = machines
        all_ok = True
        for module_instance_name, ssh_info in self.running_machines.items():
            base_module_name = ''.join(filter(str.isalpha, module_instance_name))
            if not self.setup_and_run_module(ssh_info, base_module_name, module_instance_name, self.TESTS_CONFIG[test_name], repo_url_with_auth, ip_map):
                all_ok = False
                break
        
        if all_ok:
            self.log_to_console("\n--- PREPARACIÓN DE MÓDULOS FINALIZADA CON ÉXITO ---", level="success")
            self.log_to_console("Ahora puedes conectarte a cada sesión de screen y presionar 'Enter' para ejecutar.", level="info")
            self.stop_button.config(state="normal")
        else:
            self.log_to_console("\n--- PREPARACIÓN DE MÓDULOS FINALIZADA CON ERRORES ---", level="error")
        
        self.run_button.config(state="normal")

    def setup_and_run_module(self, ssh_info, base_module_name, module_instance_name, test_config, repo_url, ip_map):
        """Se conecta, clona, compila, configura y prepara un módulo para su ejecución."""
        ip, username, password = ssh_info['ip'], ssh_info['username'], ssh_info['password']
        self.log_to_console(f"\n--- Configurando módulo '{module_instance_name}' en {ip} ---", level="title")
        
        build_dir = f"/tmp/build-{uuid.uuid4()}"
        
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)

                self.log_to_console("1. Verificando sesión de screen existente...")
                # Verificar si ya existe una sesión con este nombre
                check_session_cmd = f"screen -list | grep -q '{module_instance_name}'"
                _, stdout, stderr = ssh.exec_command(check_session_cmd, timeout=30)
                session_exists = stdout.channel.recv_exit_status() == 0
                
                if session_exists:
                    self.log_to_console(f"  > Sesión '{module_instance_name}' ya existe, reutilizando...")
                    # Limpiar procesos en la sesión existente
                    self._execute_remote_command(ssh, f"screen -S {module_instance_name} -p 0 -X stuff $'\\003'")
                    time.sleep(1)
                    self._execute_remote_command(ssh, f"screen -S {module_instance_name} -p 0 -X stuff $'clear\\n'")
                else:
                    self.log_to_console(f"  > No existe sesión '{module_instance_name}', se creará una nueva...")

                self.log_to_console(f"\n2. Clonando repositorio en directorio temporal: {build_dir}")
                if not self._execute_remote_command(ssh, f"mkdir -p {build_dir}"): return False
                if not self._execute_remote_command(ssh, f"git clone {repo_url} {build_dir}/{PROJECT_DIR_NAME}"): return False

                # Instalar so-commons-library
                self.log_to_console("\n2b. Clonando e instalando so-commons-library...")
                commons_dir = f"{build_dir}/so-commons-library"
                if not self._execute_remote_command(ssh, f"mkdir -p {build_dir}"): return False
                if not self._execute_remote_command(ssh, f"git clone {COMMONS_REPO_URL} {commons_dir}"): return False
                # Ejecutar make install pasando la contraseña al sudo
                self.log_to_console("  > Ejecutando make install con sudo y contraseña...")
                ssh_password = ssh_info['password']
                install_cmd = f"cd {commons_dir} && echo '{ssh_password}' | sudo -S make install"
                if not self._execute_remote_command(ssh, install_cmd): return False

                self.log_to_console("\n3. Compilando el módulo...")
                compile_command = f"cd {build_dir}/{PROJECT_DIR_NAME}/{base_module_name}/ && make clean all"
                if not self._execute_remote_command(ssh, compile_command): return False
                
                self.log_to_console("\n4. Creando directorio de ejecución persistente...")
                persistent_run_dir = f"/tmp/{module_instance_name}"
                if not self._execute_remote_command(ssh, f"mkdir -p {persistent_run_dir}"): return False

                self.log_to_console("\n5. Copiando archivos de ejecución y configuración...")
                source_executable = f"{build_dir}/{PROJECT_DIR_NAME}/{base_module_name}/bin/{base_module_name.lower()}"
                if not self._execute_remote_command(ssh, f"cp {source_executable} {persistent_run_dir}/"): return False
                
                if not self._process_and_upload_config(ssh, test_config, base_module_name, module_instance_name, persistent_run_dir, ip_map):
                    return False

                # Paso Adicional: Clonar el repositorio de pruebas para el módulo de memoria
                if base_module_name == "memoria":
                    self.log_to_console("\n5b. Clonando repositorio de pruebas para Memoria...")
                    pruebas_repo_url_authed = PRUEBAS_REPO_URL.replace("https://", f"https://{self.github_user_entry.get()}:{self.github_token_entry.get()}@")
                    if not self._execute_remote_command(ssh, f"rm -rf {PRUEBAS_REPO_PATH}"): return False
                    if not self._execute_remote_command(ssh, f"mkdir -p /home/utnso"): return False
                    if not self._execute_remote_command(ssh, f"git clone {pruebas_repo_url_authed} {PRUEBAS_REPO_PATH}"): return False

                self.log_to_console("\n6. Preparando el módulo en una sesión de 'screen'...")
                executable_name = base_module_name.lower()
                
                params = ""
                if base_module_name == "kernel":
                    pseudocode_file = test_config.get("pseudocode_file", "DEFAULT_PSEUDOCODE")
                    tamanio_proceso = test_config.get("tamanio_proceso", 0)
                    params = f"{pseudocode_file} {tamanio_proceso}"
                elif base_module_name == "cpu":
                    params = module_instance_name
                elif base_module_name == "io":
                    params = ssh_info.get('io_type', 'DISCO')

                command_to_paste = f"./{executable_name} {params}".strip()
                
                # Solo crear nueva sesión si no existe
                if not session_exists:
                    start_cmd = f"cd {persistent_run_dir}; exec bash"
                    screen_start_cmd = f"screen -dmS {module_instance_name} bash -c '{start_cmd}'"
                    if not self._execute_remote_command(ssh, screen_start_cmd):
                        return False
                    time.sleep(1)  # Esperar a que la sesión se inicie
                else:
                    # Cambiar al directorio correcto en la sesión existente
                    self._execute_remote_command(ssh, f"screen -S {module_instance_name} -p 0 -X stuff 'cd {persistent_run_dir}\\n'")

                screen_paste_cmd = f"screen -S {module_instance_name} -X stuff '{command_to_paste}'"
                if not self._execute_remote_command(ssh, screen_paste_cmd):
                    return False
                
                self.log_to_console(f"\n¡Módulo '{module_instance_name}' preparado en 'screen' en {ip}!", level="success")
                return True

        except Exception as e:
            self.log_to_console(f"Ocurrió un error al configurar {ip}: {e}", level="error")
            return False
        finally:
            self.log_to_console(f"\n7. Limpiando directorio de compilación {build_dir}...")
            try:
                with paramiko.SSHClient() as ssh:
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(ip, username=username, password=password, timeout=10)
                    self._execute_remote_command(ssh, f"echo '{password}' | sudo -S rm -rf {build_dir}")
            except Exception as e:
                self.log_to_console(f"  > Advertencia: No se pudo limpiar el directorio temporal {build_dir}. Error: {e}", level="warning")

    def _process_and_upload_config(self, ssh, test_config, base_module_name, module_instance_name, remote_dir, ip_map):
        """Encuentra, procesa (reemplaza IPs) y sube el archivo de configuración correcto."""
        config_folder = test_config['config_folder']
        
        instance_config_path = os.path.join(CONFIGS_BASE_PATH, config_folder, f"{module_instance_name}.config")
        generic_config_path = os.path.join(CONFIGS_BASE_PATH, config_folder, f"{base_module_name}.config")
        
        local_config_path = None
        if os.path.exists(instance_config_path):
            local_config_path = instance_config_path
            self.log_to_console(f"  > Usando configuración específica: {os.path.basename(local_config_path)}")
        elif os.path.exists(generic_config_path):
            local_config_path = generic_config_path
            self.log_to_console(f"  > Usando configuración genérica: {os.path.basename(local_config_path)}")
        
        if local_config_path:
            try:
                with open(local_config_path, 'r') as f:
                    config_content = f.read()

                for instance, ip_address in ip_map.items():
                    module_key = ''.join(filter(str.isalpha, instance)).upper()
                    config_key = f"IP_{module_key}"
                    config_content = re.sub(f"^{config_key}=.*", f"{config_key}={ip_address}", config_content, flags=re.MULTILINE)

                remote_config_file_path = f"{remote_dir}/config.cfg"
                # CORRECCIÓN: Abrir el cliente SFTP antes de usarlo
                with ssh.open_sftp() as sftp:
                    with sftp.file(remote_config_file_path, 'w') as remote_file:
                        remote_file.write(config_content)
                self.log_to_console("  > Archivo de configuración procesado y subido con éxito.", level="success")
                return True

            except Exception as e:
                self.log_to_console(f"  > Error al procesar o subir el archivo de configuración: {e}", level="error")
                return False
        
        if "io" not in base_module_name:
            self.log_to_console(f"Error: No se encontró archivo de configuración para '{module_instance_name}'", level="error")
            return False
        
        self.log_to_console(f"  > No se encontró archivo de configuración para el módulo IO '{module_instance_name}' (esto puede ser normal).", level="warning")
        return True


    def start_stop_thread(self):
        """Inicia el proceso de detención en un hilo separado."""
        self.run_button.config(state="disabled")
        self.stop_button.config(state="disabled")
        self.log_to_console("\n--- INICIANDO PROCESO DE DETENCIÓN ---", level="title")
        stop_thread = threading.Thread(target=self.run_stop_deployment, daemon=True)
        stop_thread.start()

    def run_stop_deployment(self):
        """Lógica para detener todos los módulos en ejecución."""
        if not self.running_machines:
            self.log_to_console("Error: No hay ninguna prueba en ejecución para detener.", level="error")
            self.run_button.config(state="normal")
            return

        for module_instance_name, ssh_info in self.running_machines.items():
            self.stop_module(ssh_info, module_instance_name)

        self.log_to_console("\n--- PROCESO DE DETENCIÓN FINALIZADO ---", level="success")
        self.running_machines = {}
        self.run_button.config(state="normal")

    def stop_module(self, ssh_info, module_instance_name):
        """Envía 2 Ctrl+C consecutivos a la sesión de screen sin cerrarla."""
        ip, username, password = ssh_info['ip'], ssh_info['username'], ssh_info['password']
        self.log_to_console(f"Enviando señales de interrupción a '{module_instance_name}' en {ip}...")
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)
                
                # Enviar primer Ctrl+C
                self.log_to_console(f"  > Enviando primer Ctrl+C a la sesión de screen '{module_instance_name}'...")
                ctrl_c_command1 = f"screen -S {module_instance_name} -p 0 -X stuff $'\\003'"
                self._execute_remote_command(ssh, ctrl_c_command1)
                
                # Esperar un poco y enviar segundo Ctrl+C
                time.sleep(1)
                
                self.log_to_console(f"  > Enviando segundo Ctrl+C a la sesión de screen '{module_instance_name}'...")
                ctrl_c_command2 = f"screen -S {module_instance_name} -p 0 -X stuff $'\\003'"
                self._execute_remote_command(ssh, ctrl_c_command2)
                
                self.log_to_console(f"  > Señales enviadas. La sesión de screen '{module_instance_name}' permanece activa.", level="success")
                
        except Exception as e:
            self.log_to_console(f"Error al enviar señales a {module_instance_name} en {ip}: {e}", level="error")

    def strip_ansi_codes(self, text):
        """Removes ANSI escape codes from a string."""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def _execute_remote_command(self, ssh_client, command):
        """Ejecuta un comando remoto, limpia los códigos de color y loguea la salida."""
        self.log_to_console(f"  > Ejecutando: '{command}'", level="command")
        try:
            _, stdout, stderr = ssh_client.exec_command(command, timeout=120)
            exit_status = stdout.channel.recv_exit_status()
            
            output_raw = stdout.read().decode('utf-8', errors='ignore')
            error_raw = stderr.read().decode('utf-8', errors='ignore')

            output_clean = self.strip_ansi_codes(output_raw).strip()
            error_clean = self.strip_ansi_codes(error_raw).strip()
            
            if output_clean:
                self.log_to_console("[SALIDA ESTÁNDAR]:\n" + output_clean)
            
            if error_clean:
                censored_error = error_clean.replace(self.github_token_entry.get(), '****')
                self.log_to_console("[SALIDA DE ERROR]:\n" + censored_error, level="error")
                
            if exit_status == 0:
                self.log_to_console("  > Comando ejecutado con éxito.", level="success")
            else:
                if "No screen session found" in error_raw:
                    self.log_to_console("  > (Info: No había sesión anterior para detener)", level="warning")
                else:
                    self.log_to_console(f"  > Error al ejecutar (código: {exit_status}).", level="error")
            
            return exit_status == 0 or "No screen session found" in error_raw
        except Exception as e:
            self.log_to_console(f"  > Excepción al ejecutar: {e}", level="error")
            return False

if __name__ == "__main__":
    app = TestAutomationGUI()
    app.mainloop()
