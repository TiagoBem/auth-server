/**
 * WebAuthn JavaScript for handling registration and authentication
 */

// Base64URL encoding/decoding functions
function base64UrlEncode(buffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(base64Url) {
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const binStr = atob(base64);
    const bin = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
        bin[i] = binStr.charCodeAt(i);
    }
    return bin.buffer;
}

// Status display function
function showStatus(message, isError = false) {
    const statusElement = document.getElementById('status');
    statusElement.textContent = message;
    statusElement.className = isError ? 'alert alert-danger mt-4' : 'alert alert-success mt-4';
    statusElement.style.display = 'block';
}

// Registration functions
async function startRegistration(username, displayName, email, retryCount = 0) {
    try {
        // Step 1: Send registration start request to server
        console.log("Sending request to /register/start")
        const response = await fetch('/register/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, displayName, email })
        });
        console.log("Response: ", response)

        if (!response.ok) {
            // Get detailed error message from response headers if available
            console.log("Oops, that's not good")
            const errorMessage = response.headers.get('X-Registration-Error') || 'Registration start failed';
            throw new Error(errorMessage);
        }

        const data = await response.json();

        // Step 2: Prepare credential creation options
        const publicKeyCredentialCreationOptions = {
            challenge: base64UrlDecode(data.publicKey.challenge),
            rp: data.publicKey.rp,
            user: {
                id: base64UrlDecode(data.publicKey.user.id),
                name: data.publicKey.user.name,
                displayName: data.publicKey.user.displayName
            },
            pubKeyCredParams: data.publicKey.pubKeyCredParams.map(param => {
                // Handle algorithm ID conversion more robustly
                let alg;
                try {
                    // Check if param is an object with alg property (already properly formatted)
                    if (typeof param === 'object' && param !== null && 'alg' in param) {
                        return {
                            type: 'public-key',
                            alg: param.alg
                        };
                    }

                    // Try to parse as integer first
                    alg = parseInt(param, 10);
                    // Check if parsing resulted in a valid number
                    if (isNaN(alg)) {
                        // If param is a string like "ES256", try to map it to its corresponding number
                        if (param === "ES256") alg = -7;
                        else if (param === "RS256") alg = -257;
                        else if (param === "EdDSA") alg = -8;
                        else throw new Error(`Unknown algorithm: ${param}`);
                    }
                } catch (e) {
                    console.error(`Error parsing algorithm parameter: ${param}`, e);
                    // Default to ES256 (-7) as a fallback
                    alg = -7;
                }
                return {
                    type: 'public-key',
                    alg: alg
                };
            }),
            timeout: data.publicKey.timeout,
            attestation: data.publicKey.attestation
        };

        if (data.publicKey.authenticatorSelection) {
            publicKeyCredentialCreationOptions.authenticatorSelection = data.publicKey.authenticatorSelection;
        }

        // Step 3: Create credentials using WebAuthn API
        let credential;
        try {
            credential = await navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions
            });
        } catch (error) {
            // Handle transient errors with retry mechanism
            if (error.name === 'DOMException' &&
                error.message.includes('transient reason') &&
                retryCount < 3) {
                console.log(`Transient error occurred during registration. Retrying (${retryCount + 1}/3)...`);
                // Wait a bit before retrying
                await new Promise(resolve => setTimeout(resolve, 1000));
                return startRegistration(username, displayName, email, retryCount + 1);
            }
            throw error;
        }

        // Step 4: Prepare response for server
        const registrationResponse = {
            id: credential.id,
            rawId: base64UrlEncode(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: base64UrlEncode(credential.response.attestationObject),
                clientDataJSON: base64UrlEncode(credential.response.clientDataJSON)
            }
        };

        // Safely access getTransports if it exists
        try {
            // Different browsers implement getTransports differently
            if (credential.response.getTransports && typeof credential.response.getTransports === 'function') {
                registrationResponse.response.transports = credential.response.getTransports();
            } else if (credential.response.transports) {
                // Some browsers might directly expose transports as a property
                registrationResponse.response.transports = credential.response.transports;
            } else {
                // For Firefox compatibility, try to detect browser and set common transports
                const isFirefox = navigator.userAgent.toLowerCase().indexOf('firefox') > -1;
                if (isFirefox) {
                    console.log('Firefox detected, using default transports');
                    // Use common transports for Firefox
                    registrationResponse.response.transports = ['internal', 'usb', 'ble', 'nfc'];
                }
            }
        } catch (error) {
            console.warn('Could not get transports from credential response:', error);
            // Continue without transports if there's an error
        }

        // Step 5: Send registration finish request to server
        const finishResponse = await fetch('/register/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(registrationResponse)
        });

        if (!finishResponse.ok) {
            // Get detailed error message from response headers if available
            const errorMessage = finishResponse.headers.get('X-Registration-Error') || 'Registration finish failed';
            throw new Error(errorMessage);
        }

        showStatus('Registration successful! You can now log in.');
        return true;
    } catch (error) {
        console.error('Registration error:', error);

        // Add more detailed logging for debugging
        if (error.name === 'DOMException') {
            console.error('WebAuthn DOMException details:', {
                name: error.name,
                message: error.message,
                code: error.code,
                stack: error.stack
            });

            // Detect browser for browser-specific error handling
            const isFirefox = navigator.userAgent.toLowerCase().indexOf('firefox') > -1;
            const isChrome = navigator.userAgent.toLowerCase().indexOf('chrome') > -1 && !isFirefox;

            // Log browser information for debugging
            console.log(`Browser detection: Firefox=${isFirefox}, Chrome=${isChrome}`);

            // Provide more user-friendly error message based on error type and browser
            let errorMessage = error.message;

            // Common error patterns across browsers
            if (error.message.includes('The operation either timed out') ||
                error.message.includes('timeout') ||
                error.message.includes('Timeout')) {
                errorMessage = 'The authentication operation timed out. Please try again.';
            } else if (error.message.includes('transient reason') ||
                       error.message.includes('temporarily unavailable')) {
                errorMessage = 'There was a temporary issue with your authenticator. The system attempted to retry but was unsuccessful. Please try again or use a different authenticator.';
            } else if (error.message.includes('already registered') ||
                       error.message.includes('already exists')) {
                errorMessage = 'This authenticator is already registered for this account.';
            } else if (error.message.includes('User verification') ||
                       error.message.includes('verification failed')) {
                errorMessage = 'User verification failed. Please ensure your authenticator is properly set up and try again.';
            } else if (error.message.includes('Not allowed') ||
                       error.message.includes('permission denied') ||
                       error.message.includes('not permitted')) {
                errorMessage = 'The operation was not allowed. This may be due to security settings in your browser or authenticator.';
            }

            // Firefox-specific error handling
            if (isFirefox) {
                if (error.message.includes('AbortError')) {
                    errorMessage = 'The operation was aborted. This might happen if you cancelled the authentication request or if another authentication request was initiated.';
                } else if (error.message.includes('NotAllowedError')) {
                    errorMessage = 'The operation was not allowed. This may be due to security settings in Firefox or your authenticator.';
                } else if (error.message.includes('SecurityError')) {
                    errorMessage = 'A security error occurred. Please ensure you are using Firefox in a secure context (HTTPS or localhost).';
                }
            }

            showStatus('Registration failed: ' + errorMessage, true);
        } else {
            showStatus('Registration failed: ' + error.message, true);
        }

        return false;
    }
}

// Authentication functions
async function startAuthentication(username, retryCount = 0) {
    try {
        // Step 1: Send authentication start request to server
        const response = await fetch('/login/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });

        if (!response.ok) {
            // Get detailed error message from response headers if available
            const errorMessage = response.headers.get('X-Authentication-Error') || 'Authentication start failed';
            throw new Error(errorMessage);
        }

        const data = await response.json();

        // Step 2: Prepare credential request options
        const publicKeyCredentialRequestOptions = {
            challenge: base64UrlDecode(data.publicKey.challenge),
            rpId: data.publicKey.rpId,
            timeout: data.publicKey.timeout,
            userVerification: data.publicKey.userVerification
        };

        if (data.publicKey.allowCredentials && data.publicKey.allowCredentials.length > 0) {
            publicKeyCredentialRequestOptions.allowCredentials = data.publicKey.allowCredentials.map(cred => ({
                id: base64UrlDecode(cred.id),
                type: cred.type,
                transports: cred.transports
            }));
        }

        // Step 3: Get credentials using WebAuthn API
        let credential;
        try {
            credential = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });
        } catch (error) {
            // Handle transient errors with retry mechanism
            if (error.name === 'DOMException' &&
                error.message.includes('transient reason') &&
                retryCount < 3) {
                console.log(`Transient error occurred during authentication. Retrying (${retryCount + 1}/3)...`);
                // Wait a bit before retrying
                await new Promise(resolve => setTimeout(resolve, 1000));
                return startAuthentication(username, retryCount + 1);
            }
            throw error;
        }

        // Step 4: Prepare response for server
        const authenticationResponse = {
            id: credential.id,
            rawId: base64UrlEncode(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: base64UrlEncode(credential.response.authenticatorData),
                clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
                signature: base64UrlEncode(credential.response.signature)
            }
        };

        // Safely access userHandle if it exists
        try {
            // Different browsers might implement userHandle differently
            if (credential.response.userHandle) {
                // Direct property access
                authenticationResponse.response.userHandle = base64UrlEncode(credential.response.userHandle);
            } else if (credential.response.getUserHandle && typeof credential.response.getUserHandle === 'function') {
                // Method access (some browsers might implement it this way)
                const userHandle = credential.response.getUserHandle();
                if (userHandle) {
                    authenticationResponse.response.userHandle = base64UrlEncode(userHandle);
                }
            }

            // For Firefox compatibility, check if we're in Firefox and log it
            const isFirefox = navigator.userAgent.toLowerCase().indexOf('firefox') > -1;
            if (isFirefox) {
                console.log('Firefox detected during authentication, userHandle handling might differ');
            }
        } catch (error) {
            console.warn('Could not get userHandle from credential response:', error);
            // Continue without userHandle if there's an error
        }

        // Step 5: Send authentication finish request to server
        const finishResponse = await fetch('/login/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(authenticationResponse)
        });

        if (!finishResponse.ok) {
            // Get detailed error message from response headers if available
            const errorMessage = finishResponse.headers.get('X-Authentication-Error') || 'Authentication finish failed';
            throw new Error(errorMessage);
        }

        showStatus('Authentication successful! You are now logged in.');

        // Redirect to home page after successful login
//        setTimeout(() => {
//            window.location.href = '/';
//        }, 2000);

        return true;
    } catch (error) {
        console.error('Authentication error:', error);

        // Add more detailed logging for debugging
        if (error.name === 'DOMException') {
            console.error('WebAuthn DOMException details:', {
                name: error.name,
                message: error.message,
                code: error.code,
                stack: error.stack
            });

            // Detect browser for browser-specific error handling
            const isFirefox = navigator.userAgent.toLowerCase().indexOf('firefox') > -1;
            const isChrome = navigator.userAgent.toLowerCase().indexOf('chrome') > -1 && !isFirefox;

            // Log browser information for debugging
            console.log(`Browser detection: Firefox=${isFirefox}, Chrome=${isChrome}`);

            // Provide more user-friendly error message based on error type and browser
            let errorMessage = error.message;

            // Common error patterns across browsers
            if (error.message.includes('The operation either timed out') ||
                error.message.includes('timeout') ||
                error.message.includes('Timeout')) {
                errorMessage = 'The authentication operation timed out. Please try again.';
            } else if (error.message.includes('transient reason') ||
                       error.message.includes('temporarily unavailable')) {
                errorMessage = 'There was a temporary issue with your authenticator. The system attempted to retry but was unsuccessful. Please try again or use a different authenticator.';
            } else if (error.message.includes('User verification') ||
                       error.message.includes('verification failed')) {
                errorMessage = 'User verification failed. Please ensure your authenticator is properly set up and try again.';
            } else if (error.message.includes('Not allowed') ||
                       error.message.includes('permission denied') ||
                       error.message.includes('not permitted')) {
                errorMessage = 'The operation was not allowed. This may be due to security settings in your browser or authenticator.';
            } else if (error.message.includes('no matching credential') ||
                       error.message.includes('credential not found') ||
                       error.message.includes('not recognized')) {
                errorMessage = 'No matching credential found. Please ensure you are using the correct authenticator that was registered with this account.';
            }

            // Firefox-specific error handling
            if (isFirefox) {
                if (error.message.includes('AbortError')) {
                    errorMessage = 'The operation was aborted. This might happen if you cancelled the authentication request or if another authentication request was initiated.';
                } else if (error.message.includes('NotAllowedError')) {
                    errorMessage = 'The operation was not allowed. This may be due to security settings in Firefox or your authenticator.';
                } else if (error.message.includes('SecurityError')) {
                    errorMessage = 'A security error occurred. Please ensure you are using Firefox in a secure context (HTTPS or localhost).';
                } else if (error.message.includes('InvalidStateError')) {
                    errorMessage = 'The authenticator is in an invalid state. This might happen if you are trying to use an authenticator that is already in use by another application.';
                }
            }

            showStatus('Authentication failed: ' + errorMessage, true);
        } else {
            showStatus('Authentication failed: ' + error.message, true);
        }

        return false;
    }
}

// Check if WebAuthn is supported by the browser
function isWebAuthnSupported() {
    console.log("isWebAuthnSupported called...")
    // Detect browser
    const userAgent = navigator.userAgent.toLowerCase();
    const isFirefox = userAgent.indexOf('firefox') > -1;
    const isChrome = userAgent.indexOf('chrome') > -1 && !isFirefox;
    const isEdge = userAgent.indexOf('edg') > -1;
    const isSafari = userAgent.indexOf('safari') > -1 && !isChrome && !isEdge;

    console.log(`Browser detection: Firefox=${isFirefox}, Chrome=${isChrome}, Edge=${isEdge}, Safari=${isSafari}`);

    // Basic check for PublicKeyCredential
    const basicSupport = window.PublicKeyCredential !== undefined &&
                         typeof window.PublicKeyCredential === 'function';

    if (!basicSupport) {
        console.error('Basic WebAuthn API not supported in this browser');
        return false;
    }

    // Check for secure context
    if (!window.isSecureContext) {
        console.warn('WebAuthn requires a secure context (HTTPS or localhost)');
        return false;
    }

    // Browser-specific checks and logging
    if (isFirefox) {
        console.log('Firefox detected. Ensuring Firefox-specific compatibility.');
        // Firefox supports WebAuthn since version 60, but implementation details may vary
        // Log Firefox version for debugging
        const firefoxVersion = userAgent.match(/firefox\/(\d+)/);
        if (firefoxVersion && firefoxVersion[1]) {
            console.log(`Firefox version: ${firefoxVersion[1]}`);
            if (parseInt(firefoxVersion[1]) < 67) {
                console.warn('Firefox versions below 67 may have limited WebAuthn support');
            }
        }
    } else if (isChrome) {
        console.log('Chrome detected. Chrome has good WebAuthn support.');
        // Chrome supports WebAuthn since version 67
    } else if (isEdge) {
        console.log('Edge detected. Edge has good WebAuthn support in newer versions.');
    } else if (isSafari) {
        console.log('Safari detected. Safari added WebAuthn support in version 13.');
    }

    // Check for isUserVerifyingPlatformAuthenticatorAvailable if available
    // This is an optional check that can help determine if platform authenticator is available
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        console.log('Browser supports advanced WebAuthn features');
    } else {
        console.warn('Browser supports basic WebAuthn but may lack advanced features');
    }

    return true;
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {

    // Detect browser for more specific messages
    const userAgent = navigator.userAgent.toLowerCase();
    const isFirefox = userAgent.indexOf('firefox') > -1;
    const isChrome = userAgent.indexOf('chrome') > -1 && !isFirefox;
    const isEdge = userAgent.indexOf('edg') > -1;
    const isSafari = userAgent.indexOf('safari') > -1 && !isChrome && !isEdge;

    // Check WebAuthn support
    if (!isWebAuthnSupported()) {
        let errorMessage = 'WebAuthn is not supported by your browser. Please use a modern browser that supports WebAuthn.';

        // Provide more specific error messages based on the environment
        if (!window.isSecureContext) {
            errorMessage = 'WebAuthn requires a secure context (HTTPS or localhost). Please access this site via HTTPS.';
        } else if (!navigator.credentials) {
            errorMessage = 'Your browser does not support the Credentials API required for WebAuthn.';
        }

        // Add browser-specific messages
        if (isFirefox) {
            const firefoxVersion = userAgent.match(/firefox\/(\d+)/);
            if (firefoxVersion && firefoxVersion[1] && parseInt(firefoxVersion[1]) < 60) {
                errorMessage += ' You are using Firefox ' + firefoxVersion[1] + ', but WebAuthn requires Firefox 60 or later.';
            } else {
                errorMessage += ' Although you are using Firefox, which should support WebAuthn, there might be an issue with your configuration or Firefox version.';
            }
        } else if (isChrome) {
            const chromeVersion = userAgent.match(/chrome\/(\d+)/);
            if (chromeVersion && chromeVersion[1] && parseInt(chromeVersion[1]) < 67) {
                errorMessage += ' You are using Chrome ' + chromeVersion[1] + ', but WebAuthn requires Chrome 67 or later.';
            }
        }

        showStatus(errorMessage, true);

        // Disable forms
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.title = 'WebAuthn not supported';
            }
        });

        console.error('WebAuthn is not supported by this browser:', errorMessage);
        return;
    }

    // Add browser-specific information for supported browsers
    if (isFirefox) {
        console.log('Using Firefox with WebAuthn support. Ensuring Firefox-specific compatibility.');
    } else if (isChrome) {
        console.log('Using Chrome with WebAuthn support.');
    }

    // Check if platform authenticator is available (optional)
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
            .then(available => {
                if (!available) {
                    console.warn('Platform authenticator is not available. Users may need to use a security key.');
                    // This is just a warning, not an error that prevents usage
                }
            })
            .catch(error => {
                console.warn('Error checking platform authenticator:', error);
            });
    }

    // Registration form submission
    const registrationForm = document.getElementById('registrationForm');
    if (registrationForm) {
        console.log("Enter registration if...")
        registrationForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const displayName = document.getElementById('displayName').value;
            const email = document.getElementById('email').value;
            console.log("Calling registration...")
            await startRegistration(username, displayName, email);
        });
    }

    // Authentication form submission
    const authenticationForm = document.getElementById('authenticationForm');
    if (authenticationForm) {
        authenticationForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            const username = document.getElementById('loginUsername').value;
            await startAuthentication(username);
        });
    }
});