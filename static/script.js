/**
 * AegisCyber AI - Frontend Controller Script (script.js)
 * Manages form validation, Fetch API HTTP requests, dynamic UI rendering,
 * SVG gauge animations, and SQLite audit history logs.
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Element References
    const form = document.getElementById('risk-assessment-form');
    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const btnSpinner = submitBtn.querySelector('.btn-spinner');
    const formErrorBanner = document.getElementById('form-error-banner');
    const formErrorText = document.getElementById('form-error-text');

    // Dashboard Elements
    const dashboardSection = document.getElementById('dashboard');
    const dashCompanyName = document.getElementById('dash-company-name');
    const dashTimestamp = document.getElementById('dash-timestamp');
    const gaugeFill = document.getElementById('gauge-fill');
    const gaugeScoreValue = document.getElementById('gauge-score-value');
    const riskLevelBadge = document.getElementById('risk-level-badge');
    const aiExplanationText = document.getElementById('ai-explanation-text');
    const metaIndustry = document.getElementById('meta-industry');
    const metaEmployees = document.getElementById('meta-employees');
    const riskBreakdownContainer = document.getElementById('risk-breakdown-container');
    const recommendationsContainer = document.getElementById('recommendations-container');

    // Audit History Elements
    const historyTableBody = document.getElementById('history-table-body');
    const refreshHistoryBtn = document.getElementById('refresh-history-btn');

    // Modal Elements
    const historyModal = document.getElementById('history-modal');
    const modalClose = document.getElementById('modal-close');
    const modalBody = document.getElementById('modal-body');

    // Initial History Load
    loadAssessmentHistory();

    // Event Listener: Form Submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Hide previous errors
        hideFormError();

        // Validate Form Fields Client-Side
        const isValid = validateFormInputs();
        if (!isValid) {
            showFormError("Please fill out all required fields marked with * correctly.");
            return;
        }

        // Gather Input Form Data
        const formData = new FormData(form);
        const payload = {
            company_name: formData.get('company_name').trim(),
            industry: formData.get('industry'),
            employees: parseInt(formData.get('employees'), 10),
            uses_mfa: formData.get('uses_mfa'),
            firewall_enabled: formData.get('firewall_enabled'),
            antivirus_installed: formData.get('antivirus_installed'),
            backup_strategy: formData.get('backup_strategy'),
            password_policy: formData.get('password_policy'),
            public_wifi_usage: formData.get('public_wifi_usage'),
            employee_training: formData.get('employee_training'),
            cloud_provider: formData.get('cloud_provider'),
            email_security: formData.get('email_security'),
            previous_incidents: parseInt(formData.get('previous_incidents'), 10)
        };

        // UI Loading State
        setSubmittingState(true);

        try {
            const response = await fetch('/risk', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                const errorMsg = data.error || `Server responded with status ${response.status}`;
                showFormError(errorMsg);
                setSubmittingState(false);
                return;
            }

            // Render Results on Dashboard
            renderDashboardResults(data);

            // Refresh History Table
            loadAssessmentHistory();

            // Smooth scroll to Dashboard section
            dashboardSection.classList.remove('hidden');
            dashboardSection.scrollIntoView({ behavior: 'smooth' });

        } catch (err) {
            console.error("Fetch API Error:", err);
            showFormError("Failed to connect to the cybersecurity risk server. Please ensure server.py is running.");
        } finally {
            setSubmittingState(false);
        }
    });

    // Event Listener: Refresh History Button
    if (refreshHistoryBtn) {
        refreshHistoryBtn.addEventListener('click', () => {
            loadAssessmentHistory();
        });
    }

    // Modal Close Listeners
    if (modalClose) {
        modalClose.addEventListener('click', () => {
            historyModal.classList.add('hidden');
        });
    }

    window.addEventListener('click', (e) => {
        if (e.target === historyModal) {
            historyModal.classList.add('hidden');
        }
    });

    /**
     * Client-side form input validation.
     */
    function validateFormInputs() {
        let valid = true;

        const companyInput = document.getElementById('company_name');
        const errCompany = document.getElementById('err-company_name');
        if (!companyInput.value.trim() || companyInput.value.trim().length < 2) {
            companyInput.classList.add('invalid');
            errCompany.textContent = "Company name must be at least 2 characters.";
            valid = false;
        } else {
            companyInput.classList.remove('invalid');
            errCompany.textContent = "";
        }

        const industrySelect = document.getElementById('industry');
        const errIndustry = document.getElementById('err-industry');
        if (!industrySelect.value) {
            industrySelect.classList.add('invalid');
            errIndustry.textContent = "Please select an industry.";
            valid = false;
        } else {
            industrySelect.classList.remove('invalid');
            errIndustry.textContent = "";
        }

        const empInput = document.getElementById('employees');
        const errEmp = document.getElementById('err-employees');
        const empVal = parseInt(empInput.value, 10);
        if (isNaN(empVal) || empVal < 1) {
            empInput.classList.add('invalid');
            errEmp.textContent = "Employees count must be 1 or greater.";
            valid = false;
        } else {
            empInput.classList.remove('invalid');
            errEmp.textContent = "";
        }

        const incInput = document.getElementById('previous_incidents');
        const errInc = document.getElementById('err-previous_incidents');
        const incVal = parseInt(incInput.value, 10);
        if (isNaN(incVal) || incVal < 0) {
            incInput.classList.add('invalid');
            errInc.textContent = "Previous incidents cannot be negative.";
            valid = false;
        } else {
            incInput.classList.remove('invalid');
            errInc.textContent = "";
        }

        return valid;
    }

    /**
     * Toggles submit button loading animation.
     */
    function setSubmittingState(isSubmitting) {
        if (isSubmitting) {
            submitBtn.disabled = true;
            btnText.classList.add('hidden');
            btnSpinner.classList.remove('hidden');
        } else {
            submitBtn.disabled = false;
            btnText.classList.remove('hidden');
            btnSpinner.classList.add('hidden');
        }
    }

    function showFormError(msg) {
        formErrorText.textContent = msg;
        formErrorBanner.classList.remove('hidden');
    }

    function hideFormError() {
        formErrorBanner.classList.add('hidden');
    }

    /**
     * Renders risk score, gauge animation, breakdown cards, and AI recommendations.
     */
    function renderDashboardResults(data) {
        dashCompanyName.textContent = `${data.company_name} - Cybersecurity Audit`;
        dashTimestamp.textContent = `Report Generated: ${new Date().toLocaleString()}`;
        
        metaIndustry.textContent = data.industry;
        metaEmployees.textContent = `${data.employees} Staff`;

        const score = data.risk_score;
        const level = data.risk_level;

        // Animate Score Counter
        animateCounter(gaugeScoreValue, 0, score, 1200);

        // Update Gauge SVG Circle Fill (Max Circumference ~ 502)
        const maxOffset = 502;
        const offset = maxOffset - (maxOffset * (score / 100));
        gaugeFill.style.strokeDashoffset = offset;

        // Apply Gauge & Badge Colors based on Risk Level
        riskLevelBadge.className = 'badge-level';
        if (level === 'Low') {
            riskLevelBadge.classList.add('level-low');
            gaugeFill.style.stroke = 'var(--risk-low)';
        } else if (level === 'Medium') {
            riskLevelBadge.classList.add('level-medium');
            gaugeFill.style.stroke = 'var(--risk-medium)';
        } else if (level === 'High') {
            riskLevelBadge.classList.add('level-high');
            gaugeFill.style.stroke = 'var(--risk-high)';
        } else {
            riskLevelBadge.classList.add('level-critical');
            gaugeFill.style.stroke = 'var(--risk-critical)';
        }
        riskLevelBadge.textContent = level;

        // Render AI Executive Summary
        aiExplanationText.textContent = data.ai_explanation;

        // Render Risk Factor Breakdown Cards
        riskBreakdownContainer.innerHTML = '';
        if (data.risk_breakdown && data.risk_breakdown.length > 0) {
            data.risk_breakdown.forEach(item => {
                const card = document.createElement('div');
                const sevClass = item.severity === 'High' ? 'sev-high' : item.severity === 'Medium' ? 'sev-medium' : 'sev-low';
                card.className = `breakdown-card ${sevClass}`;
                card.innerHTML = `
                    <div class="breakdown-header">
                        <span class="breakdown-factor">${escapeHtml(item.factor)}</span>
                        <span class="breakdown-impact">${escapeHtml(item.impact)}</span>
                    </div>
                    <div class="breakdown-details">${escapeHtml(item.details)}</div>
                `;
                riskBreakdownContainer.appendChild(card);
            });
        } else {
            riskBreakdownContainer.innerHTML = `
                <div class="breakdown-card sev-low">
                    <div class="breakdown-header">
                        <span class="breakdown-factor">No Critical Security Deficiencies Detected</span>
                        <span class="breakdown-impact">+0 Risk Points</span>
                    </div>
                    <div class="breakdown-details">All audited perimeter and access controls satisfy core baseline security standards.</div>
                </div>
            `;
        }

        // Render Action Recommendations
        recommendationsContainer.innerHTML = '';
        if (data.recommendations && data.recommendations.length > 0) {
            data.recommendations.forEach(rec => {
                const card = document.createElement('div');
                card.className = 'rec-card';

                const priorityClass = rec.priority === 'High' ? 'priority-high' : rec.priority === 'Medium' ? 'priority-medium' : 'priority-low';
                
                let stepsHtml = '';
                if (rec.action_steps && rec.action_steps.length > 0) {
                    stepsHtml = '<ul class="rec-steps">' + rec.action_steps.map(s => `<li>${escapeHtml(s)}</li>`).join('') + '</ul>';
                }

                card.innerHTML = `
                    <div class="rec-header">
                        <div class="rec-title-group">
                            <span class="rec-category">${escapeHtml(rec.category || 'Security Guidance')}</span>
                            <span class="rec-title">${escapeHtml(rec.title)}</span>
                        </div>
                        <span class="badge-priority ${priorityClass}">${escapeHtml(rec.priority)} Priority</span>
                    </div>
                    <div class="rec-desc">${escapeHtml(rec.description)}</div>
                    ${stepsHtml}
                `;
                recommendationsContainer.appendChild(card);
            });
        }
    }

    /**
     * Fetches and renders recent assessment submissions in history table.
     */
    async function loadAssessmentHistory() {
        try {
            historyTableBody.innerHTML = '<tr><td colspan="8" class="text-center py-4"><i class="fa-solid fa-spinner fa-spin"></i> Fetching audit logs...</td></tr>';
            
            const response = await fetch('/risk?limit=20');
            const result = await response.json();

            if (!response.ok || !result.success) {
                historyTableBody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Failed to load audit history.</td></tr>';
                return;
            }

            const records = result.data || [];
            if (records.length === 0) {
                historyTableBody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">No security assessments recorded yet. Submit the form above to log an entry.</td></tr>';
                return;
            }

            historyTableBody.innerHTML = '';
            records.forEach(rec => {
                const tr = document.createElement('tr');
                
                const levelClass = rec.risk_level === 'Low' ? 'level-low' : 
                                   rec.risk_level === 'Medium' ? 'level-medium' : 
                                   rec.risk_level === 'High' ? 'level-high' : 'level-critical';

                const formattedDate = new Date(rec.timestamp).toLocaleString();

                tr.innerHTML = `
                    <td>#${rec.id}</td>
                    <td>${escapeHtml(formattedDate)}</td>
                    <td><strong>${escapeHtml(rec.company_name)}</strong></td>
                    <td>${escapeHtml(rec.industry)}</td>
                    <td>${rec.employees}</td>
                    <td><span class="font-mono font-bold">${rec.risk_score}/100</span></td>
                    <td><span class="badge-level ${levelClass} style="font-size:0.75rem; padding: 0.2rem 0.6rem;">${escapeHtml(rec.risk_level)}</span></td>
                    <td>
                        <button class="btn btn-secondary btn-sm view-btn" data-id="${rec.id}">
                            <i class="fa-solid fa-eye"></i> View
                        </button>
                    </td>
                `;
                historyTableBody.appendChild(tr);
            });

            // Attach event listeners to View buttons
            document.querySelectorAll('.view-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const id = e.currentTarget.getAttribute('data-id');
                    openAssessmentModal(id);
                });
            });

        } catch (err) {
            console.error("Error loading history:", err);
            historyTableBody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Error connecting to server log endpoint.</td></tr>';
        }
    }

    /**
     * Opens modal displaying full assessment breakdown.
     */
    async function openAssessmentModal(assessmentId) {
        modalBody.innerHTML = '<div class="text-center py-4"><i class="fa-solid fa-spinner fa-spin"></i> Loading record details...</div>';
        historyModal.classList.remove('hidden');

        try {
            const response = await fetch(`/risk/${assessmentId}`);
            const result = await response.json();

            if (!response.ok || !result.success) {
                modalBody.innerHTML = `<div class="alert alert-danger">${result.error || 'Failed to load details'}</div>`;
                return;
            }

            const rec = result.data;
            let recsHtml = '';
            if (rec.recommendations && rec.recommendations.length > 0) {
                recsHtml = rec.recommendations.map(r => `
                    <div style="margin-bottom: 1rem; padding: 0.75rem; background: rgba(255,255,255,0.05); border-radius: 6px;">
                        <strong>[${escapeHtml(r.priority)} Priority] ${escapeHtml(r.title)}</strong>
                        <p style="font-size: 0.85rem; color: #94a3b8;">${escapeHtml(r.description)}</p>
                    </div>
                `).join('');
            }

            modalBody.innerHTML = `
                <div style="display: flex; justify-content: space-between; margin-bottom: 1rem;">
                    <div>
                        <h4>${escapeHtml(rec.company_name)}</h4>
                        <p style="color: #94a3b8; font-size: 0.85rem;">${escapeHtml(rec.industry)} | ${rec.employees} Employees</p>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 1.5rem; font-weight: bold;">Score: ${rec.risk_score}/100</div>
                        <span class="badge-level level-${rec.risk_level.toLowerCase()}">${escapeHtml(rec.risk_level)}</span>
                    </div>
                </div>

                <div style="margin-bottom: 1.5rem;">
                    <h5 style="color: #00f2fe; margin-bottom: 0.5rem;">AI Executive Explanation:</h5>
                    <p style="font-size: 0.95rem; line-height: 1.6;">${escapeHtml(rec.ai_explanation)}</p>
                </div>

                <div>
                    <h5 style="color: #00f2fe; margin-bottom: 0.5rem;">Action Plan:</h5>
                    ${recsHtml || '<p style="color: #94a3b8;">No recommendations logged.</p>'}
                </div>
            `;

        } catch (err) {
            modalBody.innerHTML = '<div class="alert alert-danger">Error loading record details.</div>';
        }
    }

    /**
     * Counter Animation Helper.
     */
    function animateCounter(element, start, end, duration) {
        let startTime = null;

        function step(timestamp) {
            if (!startTime) startTime = timestamp;
            const progress = Math.min((timestamp - startTime) / duration, 1);
            const value = Math.floor(progress * (end - start) + start);
            element.textContent = value;
            if (progress < 1) {
                window.requestAnimationFrame(step);
            } else {
                element.textContent = end;
            }
        }

        window.requestAnimationFrame(step);
    }

    /**
     * HTML Escaping utility to prevent XSS.
     */
    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
