/**
 * Behavior Change Analysis Viewer - Main Application
 *
 * A static HTML/JS viewer for vaccine discussion thread analysis.
 * Supports AES-256 encrypted thread data.
 */

// ============================================================================
// Global State
// ============================================================================

let annotatedData = [];
let threadsData = {};
let encryptionConfig = null;
let charts = {};

// ============================================================================
// URL Parameter Handling (for Azure + SharePoint deployment)
// ============================================================================

function getDataUrls() {
    const params = new URLSearchParams(window.location.search);
    return {
        annotated: params.get('annotated') || 'data/annotated.json',
        threads: params.get('threads') || 'data/threads.encrypted',
        config: params.get('config') || 'data/encryption_config.json'
    };
}

// ============================================================================
// Decryption Functions
// ============================================================================

async function loadEncryptionConfig() {
    try {
        const urls = getDataUrls();
        const response = await fetch(urls.config);
        if (!response.ok) {
            throw new Error('Config not found');
        }
        return await response.json();
    } catch (error) {
        console.error('Failed to load encryption config:', error);
        return null;
    }
}

function decryptData(encryptedBase64, password, config) {
    try {
        // Convert base64 strings to CryptoJS WordArrays
        const salt = CryptoJS.enc.Base64.parse(config.salt);
        const iv = CryptoJS.enc.Base64.parse(config.iv);
        const ciphertext = CryptoJS.enc.Base64.parse(encryptedBase64);

        // Derive key using PBKDF2 (matching Python's settings)
        // pycryptodome uses SHA1 by default for PBKDF2
        const key = CryptoJS.PBKDF2(password, salt, {
            keySize: 256 / 32,  // 256 bits = 8 words
            iterations: config.iterations,
            hasher: CryptoJS.algo.SHA1
        });

        // Create CipherParams object
        const cipherParams = CryptoJS.lib.CipherParams.create({
            ciphertext: ciphertext
        });

        // Decrypt
        const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        // Convert to UTF-8 string
        const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);

        if (!decryptedStr) {
            throw new Error('Decryption failed - empty result');
        }

        // Parse JSON
        return JSON.parse(decryptedStr);
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

// ============================================================================
// Data Loading
// ============================================================================

async function loadAnnotatedData() {
    try {
        const urls = getDataUrls();
        const response = await fetch(urls.annotated);
        if (!response.ok) {
            throw new Error('Failed to load annotated data');
        }
        return await response.json();
    } catch (error) {
        console.error('Error loading annotated data:', error);
        return null;
    }
}

async function loadEncryptedThreads() {
    try {
        const urls = getDataUrls();
        const response = await fetch(urls.threads);
        if (!response.ok) {
            throw new Error('Failed to load encrypted threads');
        }
        return await response.text();
    } catch (error) {
        console.error('Error loading encrypted threads:', error);
        return null;
    }
}

// ============================================================================
// Authentication
// ============================================================================

async function handleUnlock() {
    const passwordInput = document.getElementById('password-input');
    const errorDiv = document.getElementById('password-error');
    const unlockBtn = document.getElementById('unlock-btn');
    const loadingOverlay = document.getElementById('loading-overlay');
    const loadingMessage = document.getElementById('loading-message');

    const password = passwordInput.value;

    if (!password) {
        errorDiv.textContent = 'Please enter a password';
        errorDiv.classList.remove('hidden');
        return;
    }

    // Show loading
    unlockBtn.disabled = true;
    unlockBtn.textContent = 'Decrypting...';
    errorDiv.classList.add('hidden');

    try {
        // Load encryption config
        loadingMessage.textContent = 'Loading configuration...';
        encryptionConfig = await loadEncryptionConfig();

        if (!encryptionConfig) {
            throw new Error('Failed to load encryption configuration');
        }

        // Load encrypted data
        loadingMessage.textContent = 'Loading encrypted data...';
        const encryptedData = await loadEncryptedThreads();

        if (!encryptedData) {
            throw new Error('Failed to load encrypted data');
        }

        // Decrypt
        loadingMessage.textContent = 'Decrypting data...';

        // Use setTimeout to allow UI to update
        await new Promise(resolve => setTimeout(resolve, 100));

        const decryptedThreads = decryptData(encryptedData, password, encryptionConfig);

        if (!decryptedThreads) {
            throw new Error('Decryption failed - incorrect password');
        }

        threadsData = decryptedThreads;

        // Load annotated data (not encrypted)
        loadingMessage.textContent = 'Loading annotations...';
        annotatedData = await loadAnnotatedData();

        if (!annotatedData) {
            throw new Error('Failed to load annotation data');
        }

        console.log(`Loaded ${annotatedData.length} annotations and ${Object.keys(threadsData).length} threads`);

        // Success - hide modal and show app
        document.getElementById('password-modal').classList.add('hidden');
        document.getElementById('main-app').classList.remove('hidden');

        // Initialize app
        initApp();

    } catch (error) {
        console.error('Unlock error:', error);
        errorDiv.textContent = 'Incorrect password or failed to load data. Please try again.';
        errorDiv.classList.remove('hidden');
        unlockBtn.disabled = false;
        unlockBtn.textContent = 'Unlock';
    }
}

// ============================================================================
// Tab Navigation
// ============================================================================

function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;

            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tabId) {
                    content.classList.add('active');
                }
            });
        });
    });
}

// ============================================================================
// Statistics Page
// ============================================================================

function updateStatistics() {
    document.getElementById('total-threads').textContent = annotatedData.length;

    const vaccineRelated = annotatedData.filter(d => d.vaccine_related).length;
    const vaccinePercent = ((vaccineRelated / annotatedData.length) * 100).toFixed(1);
    document.getElementById('vaccine-related').textContent = `${vaccineRelated} (${vaccinePercent}%)`;

    const behaviorChanges = annotatedData.filter(d => d.behavior_change_occurred).length;
    const bcPercent = ((behaviorChanges / annotatedData.length) * 100).toFixed(1);
    document.getElementById('behavior-changes').textContent = `${behaviorChanges} (${bcPercent}%)`;

    const highConf = annotatedData.filter(d => d.behavior_change_confidence === 'High').length;
    const hcPercent = ((highConf / annotatedData.length) * 100).toFixed(1);
    document.getElementById('high-confidence').textContent = `${highConf} (${hcPercent}%)`;

    renderCharts();
}

function renderCharts() {
    renderChangeTypeChart();
    renderConfidenceChart();
    renderVaccineTypeChart();
    renderStanceChart();
}

function renderChangeTypeChart() {
    const ctx = document.getElementById('change-type-chart').getContext('2d');

    const changeTypes = {};
    annotatedData.filter(d => d.behavior_change_occurred).forEach(d => {
        const type = d.behavior_change_change_type || 'Unknown';
        changeTypes[type] = (changeTypes[type] || 0) + 1;
    });

    const labels = Object.keys(changeTypes);
    const data = Object.values(changeTypes);

    if (charts.changeType) charts.changeType.destroy();

    charts.changeType = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.map(l => l.replace(/_/g, ' ')),
            datasets: [{
                label: 'Count',
                data: data,
                backgroundColor: ['#28a745', '#007bff', '#6f42c1', '#fd7e14', '#dc3545', '#6c757d'],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { maxRotation: 45, minRotation: 45 } },
                y: { beginAtZero: true }
            }
        }
    });
}

function renderConfidenceChart() {
    const ctx = document.getElementById('confidence-chart').getContext('2d');

    const confidenceCounts = { High: 0, Medium: 0, Low: 0 };
    annotatedData.forEach(d => {
        const conf = d.behavior_change_confidence || 'Low';
        if (confidenceCounts[conf] !== undefined) {
            confidenceCounts[conf]++;
        }
    });

    if (charts.confidence) charts.confidence.destroy();

    charts.confidence = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: [confidenceCounts.High, confidenceCounts.Medium, confidenceCounts.Low],
                backgroundColor: ['#28a745', '#ffc107', '#dc3545']
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'bottom' } }
        }
    });
}

function renderVaccineTypeChart() {
    const ctx = document.getElementById('vaccine-type-chart').getContext('2d');

    const vaccineTypes = {};
    annotatedData.forEach(d => {
        if (d.vaccine_types && Array.isArray(d.vaccine_types)) {
            d.vaccine_types.forEach(v => {
                vaccineTypes[v] = (vaccineTypes[v] || 0) + 1;
            });
        }
    });

    const sorted = Object.entries(vaccineTypes).sort((a, b) => b[1] - a[1]).slice(0, 10);

    if (charts.vaccineType) charts.vaccineType.destroy();

    charts.vaccineType = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s[0]),
            datasets: [{
                label: 'Count',
                data: sorted.map(s => s[1]),
                backgroundColor: '#4472C4',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true } }
        }
    });
}

function renderStanceChart() {
    const ctx = document.getElementById('stance-chart').getContext('2d');

    const transitions = {};
    annotatedData.filter(d => d.behavior_change_occurred).forEach(d => {
        const initial = d.behavior_change_initial_stance || 'Unknown';
        const final = d.behavior_change_final_stance || 'Unknown';
        const key = `${initial} → ${final}`;
        transitions[key] = (transitions[key] || 0) + 1;
    });

    const sorted = Object.entries(transitions).sort((a, b) => b[1] - a[1]).slice(0, 8);

    if (charts.stance) charts.stance.destroy();

    charts.stance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s[0]),
            datasets: [{
                label: 'Count',
                data: sorted.map(s => s[1]),
                backgroundColor: '#17a2b8',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true } }
        }
    });
}

// ============================================================================
// Search Page
// ============================================================================

function initSearch() {
    populateFilters();

    document.getElementById('filter-behavior').addEventListener('change', filterResults);
    document.getElementById('filter-change-type').addEventListener('change', filterResults);
    document.getElementById('filter-confidence').addEventListener('change', filterResults);
    document.getElementById('filter-vaccine').addEventListener('change', filterResults);

    filterResults();
}

function populateFilters() {
    const changeTypes = new Set();
    annotatedData.forEach(d => {
        if (d.behavior_change_change_type) {
            changeTypes.add(d.behavior_change_change_type);
        }
    });

    const changeTypeSelect = document.getElementById('filter-change-type');
    Array.from(changeTypes).sort().forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type.replace(/_/g, ' ');
        changeTypeSelect.appendChild(option);
    });

    const vaccineTypes = new Set();
    annotatedData.forEach(d => {
        if (d.vaccine_types && Array.isArray(d.vaccine_types)) {
            d.vaccine_types.forEach(v => vaccineTypes.add(v));
        }
    });

    const vaccineSelect = document.getElementById('filter-vaccine');
    Array.from(vaccineTypes).sort().forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type;
        vaccineSelect.appendChild(option);
    });
}

function filterResults() {
    const behaviorFilter = document.getElementById('filter-behavior').value;
    const changeTypeFilter = document.getElementById('filter-change-type').value;
    const confidenceFilter = document.getElementById('filter-confidence').value;
    const vaccineFilter = document.getElementById('filter-vaccine').value;

    let filtered = [...annotatedData];

    if (behaviorFilter !== '') {
        const filterValue = behaviorFilter === 'true';
        filtered = filtered.filter(d => d.behavior_change_occurred === filterValue);
    }

    if (changeTypeFilter !== '') {
        filtered = filtered.filter(d => d.behavior_change_change_type === changeTypeFilter);
    }

    if (confidenceFilter !== '') {
        filtered = filtered.filter(d => d.behavior_change_confidence === confidenceFilter);
    }

    if (vaccineFilter !== '') {
        filtered = filtered.filter(d => d.vaccine_types && d.vaccine_types.includes(vaccineFilter));
    }

    document.getElementById('results-count').textContent = filtered.length;
    renderSearchResults(filtered);
}

function renderSearchResults(results) {
    const container = document.getElementById('search-results');
    container.innerHTML = '';

    results.slice(0, 100).forEach(item => {
        const card = document.createElement('div');
        card.className = 'thread-card';
        card.onclick = () => viewThread(item.thread_id);

        const changeLabel = item.behavior_change_occurred
            ? (item.behavior_change_change_type || 'Change').replace(/_/g, ' ')
            : 'No Change';

        card.innerHTML = `
            <div class="thread-card-header">
                <span class="thread-card-id">Thread ${item.thread_id}</span>
                <div class="thread-card-badges">
                    ${item.behavior_change_occurred ? '<span class="badge badge-green">Changed</span>' : ''}
                    <span class="badge badge-gray">${item.behavior_change_confidence || 'N/A'}</span>
                </div>
            </div>
            <div class="thread-card-body">
                <div class="thread-card-item">
                    <label>Change Type</label>
                    <span>${changeLabel}</span>
                </div>
                <div class="thread-card-item">
                    <label>Vaccine Types</label>
                    <span>${item.vaccine_types?.join(', ') || 'N/A'}</span>
                </div>
                <div class="thread-card-item">
                    <label>Trajectory</label>
                    <span>${item.behavior_change_initial_stance || '?'} → ${item.behavior_change_final_stance || '?'}</span>
                </div>
            </div>
        `;

        container.appendChild(card);
    });

    if (results.length > 100) {
        const more = document.createElement('div');
        more.className = 'results-count';
        more.textContent = `Showing first 100 of ${results.length} results`;
        container.appendChild(more);
    }
}

// ============================================================================
// View Thread Page
// ============================================================================

function initViewThread() {
    document.getElementById('view-thread-btn').addEventListener('click', () => {
        const threadId = document.getElementById('thread-id-input').value;
        if (threadId) {
            viewThread(parseInt(threadId));
        }
    });

    document.getElementById('thread-id-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const threadId = document.getElementById('thread-id-input').value;
            if (threadId) {
                viewThread(parseInt(threadId));
            }
        }
    });

    populateQuickAccess();
}

function populateQuickAccess() {
    const highConfContainer = document.getElementById('quick-high-conf');
    const highConf = annotatedData
        .filter(d => d.behavior_change_occurred && d.behavior_change_confidence === 'High')
        .slice(0, 5);

    highConf.forEach(item => {
        const btn = document.createElement('button');
        btn.className = 'quick-btn';
        btn.textContent = `Thread ${item.thread_id}`;
        btn.onclick = () => viewThread(item.thread_id);
        highConfContainer.appendChild(btn);
    });

    const lowConfContainer = document.getElementById('quick-low-conf');
    const lowConf = annotatedData
        .filter(d => d.behavior_change_confidence === 'Low')
        .slice(0, 5);

    lowConf.forEach(item => {
        const btn = document.createElement('button');
        btn.className = 'quick-btn';
        btn.textContent = `Thread ${item.thread_id}`;
        btn.onclick = () => viewThread(item.thread_id);
        lowConfContainer.appendChild(btn);
    });
}

function viewThread(threadId) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === 'view');
    });
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === 'view');
    });

    document.getElementById('thread-id-input').value = threadId;

    const annotation = annotatedData.find(d => d.thread_id === threadId);
    const posts = threadsData[String(threadId)];

    const display = document.getElementById('thread-display');

    if (!annotation) {
        display.innerHTML = '<div class="empty">Thread not found in annotations</div>';
        return;
    }

    if (!posts) {
        display.innerHTML = '<div class="empty">Thread content not found</div>';
        return;
    }

    display.innerHTML = renderThreadContent(annotation, posts);
}

function renderThreadContent(annotation, posts) {
    const annotationHTML = `
        <div class="annotation-result">
            <h3>Annotation Results</h3>
            <div class="annotation-grid">
                <div class="annotation-item">
                    <label>Thread ID</label>
                    <div class="value">${annotation.thread_id}</div>
                </div>
                <div class="annotation-item">
                    <label>Behavior Change</label>
                    <div class="value">${annotation.behavior_change_occurred ? '✓ Yes' : '✗ No'}</div>
                </div>
                <div class="annotation-item">
                    <label>Confidence</label>
                    <div class="value confidence-${(annotation.behavior_change_confidence || 'low').toLowerCase()}">
                        ${annotation.behavior_change_confidence || 'N/A'}
                    </div>
                </div>
                <div class="annotation-item">
                    <label>Vaccine Types</label>
                    <div class="value">${annotation.vaccine_types?.join(', ') || 'N/A'}</div>
                </div>
                ${annotation.behavior_change_occurred ? `
                    <div class="annotation-item">
                        <label>Change Type</label>
                        <div class="value">${(annotation.behavior_change_change_type || 'N/A').replace(/_/g, ' ')}</div>
                    </div>
                    <div class="annotation-item">
                        <label>Initial Stance</label>
                        <div class="value">${annotation.behavior_change_initial_stance || 'N/A'}</div>
                    </div>
                    <div class="annotation-item">
                        <label>Final Stance</label>
                        <div class="value">${annotation.behavior_change_final_stance || 'N/A'}</div>
                    </div>
                    <div class="annotation-item">
                        <label>Turning Point</label>
                        <div class="value">${annotation.behavior_change_key_turning_point_post_number ? 'Post #' + annotation.behavior_change_key_turning_point_post_number : 'N/A'}</div>
                    </div>
                ` : ''}
            </div>
            ${annotation.reasoning ? `
                <div class="annotation-reasoning">
                    <h4>Reasoning</h4>
                    <p>${escapeHtml(annotation.reasoning)}</p>
                </div>
            ` : ''}
        </div>
    `;

    const turningPoint = annotation.behavior_change_key_turning_point_post_number;
    const influentialPost = annotation.behavior_change_influenced_by_post_number;

    const postsHTML = posts.map((post, idx) => {
        const postNum = idx + 1;
        const isTurningPoint = turningPoint && postNum === turningPoint;
        const isInfluential = influentialPost && postNum === influentialPost;
        const hasVaccineKeyword = post.has_vaccine_keyword;

        const classes = ['post-item'];
        if (isTurningPoint) classes.push('turning-point');
        if (isInfluential) classes.push('influential');
        if (hasVaccineKeyword) classes.push('vaccine-keyword');

        const badges = [];
        if (isTurningPoint) badges.push('<span class="badge badge-yellow">Turning Point</span>');
        if (isInfluential) badges.push('<span class="badge badge-cyan">Influential</span>');
        if (hasVaccineKeyword) badges.push('<span class="badge badge-green">Vaccine</span>');

        return `
            <div class="${classes.join(' ')}">
                <div class="post-header">
                    <div class="post-meta">
                        <span><strong>Post #${postNum}</strong></span>
                        <span>${post.author_role}</span>
                        <span>${post.timestamp}</span>
                        <span>Sentiment: ${post.sentiment}</span>
                        ${post.replies_to_post_number ? `<span>Reply to #${post.replies_to_post_number}</span>` : ''}
                    </div>
                    <div class="post-badges">
                        ${badges.join('')}
                    </div>
                </div>
                <div class="post-content">${escapeHtml(post.content)}</div>
            </div>
        `;
    }).join('');

    return `
        ${annotationHTML}
        <div class="post-list">
            <h3>Thread Content (${posts.length} posts)</h3>
            ${postsHTML}
        </div>
    `;
}

// ============================================================================
// Utilities
// ============================================================================

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// App Initialization
// ============================================================================

function initApp() {
    initTabs();
    updateStatistics();
    initSearch();
    initViewThread();
    console.log('Application initialized');
}

// ============================================================================
// Entry Point
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Setup unlock button
    document.getElementById('unlock-btn').addEventListener('click', handleUnlock);

    // Allow Enter key to unlock
    document.getElementById('password-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleUnlock();
        }
    });

    // Focus password input
    document.getElementById('password-input').focus();
});
