require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();

// IMPORTANT: Raw body capture for Slack signature verification
app.use('/slack', express.raw({ type: 'application/x-www-form-urlencoded' }));
app.use(express.json());

// Slack signature verification
function verifySlackSignature(req, res, next) {
  const slackSignature = req.headers['x-slack-signature'];
  const timestamp = req.headers['x-slack-request-timestamp'];
  const signingSecret = process.env.SLACK_SIGNING_SECRET;
  
  if (!slackSignature || !timestamp) {
    return res.status(401).send('Unauthorized');
  }
  
  // Check timestamp to prevent replay attacks
  const currentTime = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTime - timestamp) > 300) {
    return res.status(401).send('Request timeout');
  }
  
  // Get raw body and parse it
  const rawBody = req.body.toString('utf8');
  req.body = Object.fromEntries(new URLSearchParams(rawBody));
  
  // Create signature
  const sigBasestring = `v0:${timestamp}:${rawBody}`;
  const mySignature = 'v0=' + crypto
    .createHmac('sha256', signingSecret)
    .update(sigBasestring)
    .digest('hex');
  
  // Compare signatures
  if (crypto.timingSafeEqual(
    Buffer.from(mySignature, 'utf8'),
    Buffer.from(slackSignature, 'utf8')
  )) {
    next();
  } else {
    console.log('Signature verification failed');
    return res.status(401).send('Unauthorized');
  }
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Slack API wrapper
class SlackAPI {
  constructor(token) {
    this.token = token;
    this.baseURL = 'https://slack.com/api';
  }
  
  async request(method, data = {}) {
    try {
      const response = await axios.post(`${this.baseURL}/${method}`, data, {
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json'
        }
      });
      return response.data;
    } catch (error) {
      console.error(`Slack API error (${method}):`, error.response?.data || error.message);
      throw error;
    }
  }
  
  async postMessage(channel, text, blocks = null) {
    const payload = { channel, text };
    if (blocks) payload.blocks = blocks;
    return this.request('chat.postMessage', payload);
  }
  
  async postEphemeral(channel, user, text) {
    return this.request('chat.postEphemeral', { channel, user, text });
  }
}

const slack = new SlackAPI(process.env.SLACK_BOT_TOKEN);

// SessionBoard knowledge base scraper
class SessionBoardSearch {
  constructor() {
    this.baseUrl = 'https://learn.sessionboard.com/en/knowledge-base';
    this.cache = new Map();
  }

  async searchKnowledgeBase(query) {
    try {
      // First, get the main knowledge base page to find article links
      const response = await axios.get(this.baseUrl);
      const $ = cheerio.load(response.data);
      
      const articles = [];
      
      // Extract article links and titles
      $('a[href*="/knowledge-base/"]').each((i, element) => {
        const title = $(element).text().trim();
        const href = $(element).attr('href');
        if (title && href && title.length > 3) {
          articles.push({
            title: title,
            url: href.startsWith('http') ? href : `https://learn.sessionboard.com${href}`
          });
        }
      });

      // Search through articles for relevant content
      const searchResults = await this.searchArticles(articles, query);
      return searchResults;
      
    } catch (error) {
      console.error('Search error:', error);
      return [];
    }
  }

  async searchArticles(articles, query) {
    const queryLower = query.toLowerCase();
    const results = [];
    
    for (const article of articles.slice(0, 10)) { // Limit to prevent rate limiting
      try {
        if (this.cache.has(article.url)) {
          const content = this.cache.get(article.url);
          if (this.contentMatches(content, queryLower)) {
            results.push({
              ...article,
              snippet: this.extractSnippet(content, queryLower)
            });
          }
        } else {
          const response = await axios.get(article.url);
          const $ = cheerio.load(response.data);
          const content = $('body').text().toLowerCase();
          
          this.cache.set(article.url, content);
          
          if (this.contentMatches(content, queryLower)) {
            results.push({
              ...article,
              snippet: this.extractSnippet(content, queryLower)
            });
          }
        }
        
        // Add delay to be respectful
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (error) {
        console.error(`Error fetching ${article.url}:`, error.message);
      }
    }
    
    return results.slice(0, 5); // Return top 5 results
  }

  contentMatches(content, query) {
    return content.includes(query) || 
           query.split(' ').some(word => content.includes(word));
  }

  extractSnippet(content, query) {
    const index = content.indexOf(query);
    if (index === -1) return '';
    
    const start = Math.max(0, index - 100);
    const end = Math.min(content.length, index + 200);
    return content.substring(start, end).trim() + '...';
  }
}

const searcher = new SessionBoardSearch();

// Slash command handler
app.post('/slack/commands', verifySlackSignature, async (req, res) => {
  try {
    console.log('Slash command received:', req.body);
    
    const { command, text, user_id, channel_id } = req.body;
    
    if (command === '/sbhelp') {  // Changed to match your command
      // Respond immediately to avoid timeout
      res.json({
        response_type: 'ephemeral',
        text: 'Searching SessionBoard knowledge base...'
      });
      
      try {
        const results = await searcher.searchKnowledgeBase(text || 'getting started');
        await sendSearchResults(channel_id, user_id, text, results);
      } catch (error) {
        console.error('Search error:', error);
        await slack.postEphemeral(channel_id, user_id, 'Sorry, I encountered an error while searching. Please try again.');
      }
    } else {
      res.json({
        response_type: 'ephemeral',
        text: 'Unknown command'
      });
    }
  } catch (error) {
    console.error('Command handler error:', error);
    res.status(500).json({ 
      response_type: 'ephemeral',
      text: 'Internal server error' 
    });
  }
});

// Event handler
app.post('/slack/events', express.json(), (req, res) => {
  if (req.body.type === 'url_verification') {
    return res.json({ challenge: req.body.challenge });
  }
  
  // For actual events, verify signature
  res.status(200).send();
});

async function sendSearchResults(channel, user, query, results) {
  if (results.length === 0) {
    await slack.postMessage(
      channel,
      `No results found for "${query}". Try searching for general topics like "getting started", "setup", or "features".`
    );
    return;
  }

  const blocks = [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*SessionBoard Knowledge Base Results for "${query}"*`
      }
    },
    {
      type: 'divider'
    }
  ];

  results.forEach((result, index) => {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*<${result.url}|${result.title}>*\n${result.snippet || 'Click to read more...'}`
      }
    });
    
    if (index < results.length - 1) {
      blocks.push({ type: 'divider' });
    }
  });

  blocks.push({
    type: 'context',
    elements: [
      {
        type: 'mrkdwn',
        text: 'Use `/sbhelp [your question]` to search again'
      }
    ]
  });

  await slack.postMessage(channel, `Found ${results.length} results for "${query}"`, blocks);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`SessionBoard Slack app listening on port ${PORT}`);
  console.log('Config:', {
    HAS_SECRET: !!process.env.SLACK_SIGNING_SECRET,
    HAS_TOKEN: !!process.env.SLACK_BOT_TOKEN
  });
});
