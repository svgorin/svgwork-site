class CopyableText extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        const text = this.getAttribute('text') || '';

        this.shadowRoot.innerHTML = `
            <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" />
            <style>
                :host {
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                }
                .copy-icon {
                    cursor: pointer;
                    user-select: none;
                }
            </style>
            <div id="key-text">${text}</div>
            <span id="copy-button" class="material-symbols-outlined copy-icon">content_copy</span>
        `;

        this.shadowRoot.getElementById('copy-button').addEventListener('click', () => {
            const textToCopy = this.shadowRoot.getElementById('key-text').textContent;
            navigator.clipboard.writeText(textToCopy).then(() => {
                console.log('Text copied to clipboard successfully!');
            }).catch(err => console.error('Failed to copy text: ', err));
        });
    }
}

customElements.define('copyable-text', CopyableText);
