from burp import IBurpExtender, ITab, IHttpListener, IProxyListener
from javax.swing import JPanel, JLabel, JTextField, JButton, BoxLayout
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
import base64

class MyCustomTab(JPanel):
    def __init__(self, burp_extender):
# Create 2 panels with labels and text fields
        self.panel_1 = JPanel()
        self.panel_1.setLayout(BoxLayout(self.panel_1, BoxLayout.Y_AXIS))  # Set Y_AXIS layout for vertical arrangement

        self.secret_key_label = JLabel("Secret Key (Base64 Encoded):")
        self.text_field = JTextField(20)
        self.panel_1.add(self.secret_key_label)
        self.panel_1.add(self.text_field)

        self.iv_label = JLabel("IV (Base64 Encoded):")  # Create a label for IV
        self.text_field_2 = JTextField(1)
        self.panel_1.add(self.iv_label)  # Add IV label below Secret Key label
        self.panel_1.add(self.text_field_2)

        self.burp_extender = burp_extender

        # Create a button
        self.submit_button = JButton("Start", actionPerformed=self.submit_button_clicked)

        # Create another button for Stop
        self.stop_button = JButton("Stop", actionPerformed=self.stop_button_clicked)

        # Add the panels and buttons to the main panel
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))  # Set Y_AXIS layout for vertical arrangement
        self.add(self.panel_1)
        self.add(self.submit_button)
        self.add(self.stop_button)

        

    def submit_button_clicked(self, event):
        secret_key = self.text_field.getText()
        iv = self.text_field_2.getText()
        print("Start button clicked")

        self.burp_extender.set_aes_key_iv(secret_key, iv)

    def stop_button_clicked(self, event):
        print("Stop button clicked")

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        self.callbacks.setExtensionName("New AES Killer")
        self.custom_tab = MyCustomTab(self)  # Create an instance of your custom tab
        self.callbacks.addSuiteTab(self)  # Add the custom tab to Burp's UI

        self.callbacks.registerHttpListener(self)  # Register as an HTTP listener

        self.aes_key = None
        self.iv = None

    def set_aes_key_iv(self, aes_key, iv):
        self.aes_key = base64.b64decode(aes_key)
        self.iv = base64.b64decode(iv)
    def getTabCaption(self):
        return "AES Killer"

    def getUiComponent(self):
        return self.custom_tab  # Return the custom tab's component

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            payload = self.get_payload(request)
            
            # Check if payload exists before using it
            if payload:
                print(payload)
                decrypted_text = self.decrypt_payload(payload)
                if decrypted_text:
                    print("Decryption successful:", decrypted_text)
                else:
                    print("Decryption unsuccessful")

    def get_payload(self, request):
        request_info = self.helpers.analyzeRequest(request)
        body_offset = request_info.getBodyOffset()
        request_body = request[body_offset:]

        parameters = self.helpers.bytesToString(request_body).split('&')
        formatted_payload = '&'.join(parameters)

        return formatted_payload
    
    def decrypt_payload(self, payload):
        try:
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            key_spec = SecretKeySpec(self.aes_key, "AES")
        
            iv = self.iv

            cipher.init(Cipher.DECRYPT_MODE, key_spec, IvParameterSpec(iv))

            ciphertext = base64.b64decode(payload)
            decrypted_bytes = cipher.doFinal(ciphertext)
            # print(decrypted_bytes)
            plaintext = ''.join(chr(byte) for byte in decrypted_bytes)
            return plaintext
        except Exception as e:
            return None